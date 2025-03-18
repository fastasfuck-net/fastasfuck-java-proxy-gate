// Package ipblacklist implementiert eine IP-Blacklist für Gate
package ipblacklist

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/robinbraemer/event"
	c "go.minekube.com/common/minecraft/component"
	"go.minekube.com/gate/pkg/edition/java/proxy"
)

// Plugin ist ein IP-Blacklist-Plugin, das Verbindungen von Spielern ablehnt,
// die auf einer Blacklist stehen, die regelmäßig von einer URL aktualisiert wird.
var Plugin = proxy.Plugin{
	Name: "IPBlacklist",
	Init: func(ctx context.Context, p *proxy.Proxy) error {
		log := logr.FromContextOrDiscard(ctx)
		log.Info("IP Blacklist Plugin wird initialisiert...")

		// Erstelle eine neue Instanz des Plugins
		plugin := &blacklistPlugin{
			log:            log,
			blacklist:      make(map[string]bool),
			blacklistCIDR:  make([]*net.IPNet, 0),
			proxy:          p,
			// HIER EINSTELLUNGEN ANPASSEN:
			blacklistURL:   "https://fastasfuck.net/blacklist.json", // URL zur Blacklist
			updateInterval: 5 * time.Minute,                         // Update-Intervall
			blockMessage:   "You are on the global blacklist of fastasfuck.net\nTo appeal go to appeal.fastasfuck.net",
			enabled:        true,  // Plugin aktivieren/deaktivieren
		}

		if !plugin.enabled {
			log.Info("IP Blacklist Plugin ist deaktiviert.")
			return nil
		}

		// Starte den Update-Prozess im Hintergrund
		go plugin.startBlacklistUpdater(ctx)

		// Registriere den Event-Handler für LoginEvents
		// Verwende hier die korrekte Syntax für die Event-Registrierung
		event.Subscribe(p.Event(), 0, func(e event.Event) {
			if loginEvent, ok := e.(*proxy.LoginEvent); ok {
				plugin.handleLogin(loginEvent)
			}
		})

		log.Info("IP Blacklist Plugin erfolgreich initialisiert!", 
			"blacklistURL", plugin.blacklistURL,
			"updateInterval", plugin.updateInterval)
		return nil
	},
}

type blacklistPlugin struct {
	log            logr.Logger
	blacklist      map[string]bool      // Für exakte IP-Adressen
	blacklistCIDR  []*net.IPNet         // Für IP-Bereiche (CIDR-Notation)
	blacklistMutex sync.RWMutex
	blacklistURL   string
	updateInterval time.Duration
	blockMessage   string
	enabled        bool
	proxy          *proxy.Proxy
}

// BlacklistEntry repräsentiert einen Eintrag in der Blacklist
type BlacklistEntry struct {
	IP string `json:"ip"`
}

// handleLogin wird aufgerufen, wenn ein Spieler versucht, sich zu verbinden
func (p *blacklistPlugin) handleLogin(e *proxy.LoginEvent) {
	player := e.Player()
	if player == nil {
		p.log.Error(nil, "Kein Spieler im LoginEvent")
		return
	}

	// Extrahiere die IP-Adresse
	ipAddr := extractIP(player.RemoteAddr())
	
	// Zeige IP-Adresse und Spielername in der Konsole an
	playerName := player.Username()
	if ipAddr == "" {
		p.log.Info("Spieler verbunden - IP konnte nicht extrahiert werden", 
			"spieler", playerName, 
			"addr", player.RemoteAddr())
	} else {
		// Zeige die IP-Adresse deutlich in der Konsole an
		p.log.Info("Spieler verbunden", 
			"spieler", playerName, 
			"ip", ipAddr)
	}

	// Wenn keine IP extrahiert werden konnte, brechen wir hier ab
	if ipAddr == "" {
		return
	}

	// Prüfe, ob die IP in der Blacklist ist
	if p.isBlocked(ipAddr) {
		p.log.Info("Verbindung von geblockter IP abgelehnt", "ip", ipAddr, "spieler", playerName)

		// Ablehnen der Verbindung mit einer Nachricht
		disconnectMessage := &c.Text{
			Content: p.blockMessage,
		}

		// Die Disconnect-Methode wird aufgerufen, um die Verbindung zu trennen
		player.Disconnect(disconnectMessage)
	}
}

// extractIP extrahiert die IP-Adresse aus einer Netzwerkadresse
func extractIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}

	// Versuche, die IP-Adresse aus verschiedenen Typen zu extrahieren
	var ipStr string
	switch v := addr.(type) {
	case *net.TCPAddr:
		ipStr = v.IP.String()
	case *net.UDPAddr:
		ipStr = v.IP.String()
	default:
		// Fallback für andere Adresstypen
		addrStr := addr.String()
		host, _, err := net.SplitHostPort(addrStr)
		if err != nil {
			// Wenn SplitHostPort fehlschlägt, könnte es sein, dass addrStr
			// bereits nur die IP-Adresse ist
			ipStr = addrStr
		} else {
			ipStr = host
		}
	}

	// Validiere die IP-Adresse
	if net.ParseIP(ipStr) != nil {
		return ipStr
	}
	return ""
}

// isBlocked prüft, ob eine IP-Adresse blockiert ist
func (p *blacklistPlugin) isBlocked(ipStr string) bool {
	if ipStr == "" {
		return false
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		p.log.V(1).Info("Ungültige IP-Adresse", "ip", ipStr)
		return false
	}

	// Lokale und private IPs nicht blockieren
	if ip.IsLoopback() || isPrivateIP(ip) {
		return false
	}

	p.blacklistMutex.RLock()
	defer p.blacklistMutex.RUnlock()

	// Prüfe exakte Übereinstimmung
	if p.blacklist[ipStr] {
		return true
	}

	// Prüfe CIDR-Bereiche
	for _, cidr := range p.blacklistCIDR {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

// isPrivateIP prüft, ob eine IP-Adresse im privaten Bereich liegt
func isPrivateIP(ip net.IP) bool {
	// Private IPv4 Bereiche
	privateIPv4Blocks := []string{
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"127.0.0.0/8",    // Localhost
	}

	// Private IPv6 Bereiche
	privateIPv6Blocks := []string{
		"fc00::/7",   // Unique-Local
		"fe80::/10",  // Link-Local
		"::1/128",    // Localhost
	}

	// Prüfe IPv4
	if ip.To4() != nil {
		for _, block := range privateIPv4Blocks {
			_, cidr, err := net.ParseCIDR(block)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		}
	} else { // Prüfe IPv6
		for _, block := range privateIPv6Blocks {
			_, cidr, err := net.ParseCIDR(block)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		}
	}

	return false
}

// startBlacklistUpdater startet einen Goroutine, der die Blacklist regelmäßig aktualisiert
func (p *blacklistPlugin) startBlacklistUpdater(ctx context.Context) {
	// Sofort beim Start aktualisieren
	if err := p.updateBlacklist(); err != nil {
		p.log.Error(err, "Initialer Blacklist-Update fehlgeschlagen")
	}

	// Dann regelmäßig aktualisieren
	ticker := time.NewTicker(p.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := p.updateBlacklist(); err != nil {
				p.log.Error(err, "Blacklist-Update fehlgeschlagen")
			}
		case <-ctx.Done():
			p.log.Info("Blacklist Updater beendet")
			return
		}
	}
}

// updateBlacklist lädt die aktuelle Blacklist von der konfigurierten URL
func (p *blacklistPlugin) updateBlacklist() error {
	p.log.Info("Aktualisiere IP-Blacklist...", "url", p.blacklistURL)

	// HTTP-Anfrage an die Blacklist-URL mit Kontext und Timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", p.blacklistURL, nil)
	if err != nil {
		return fmt.Errorf("fehler beim Erstellen der HTTP-Anfrage: %w", err)
	}

	// User-Agent setzen, um höflich zu sein
	req.Header.Set("User-Agent", "IPBlacklist-Plugin/1.0")

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fehler beim Abrufen der Blacklist: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unerwarteter Status-Code beim Abrufen der Blacklist: %d", resp.StatusCode)
	}

	// Lese den Response-Body mit Größenbeschränkung
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // Max 10MB
	if err != nil {
		return fmt.Errorf("fehler beim Lesen der Blacklist-Antwort: %w", err)
	}

	// Versuche verschiedene Formate zu parsen
	return p.parseBlacklist(body)
}

// parseBlacklist versucht, die Blacklist in verschiedenen Formaten zu parsen
func (p *blacklistPlugin) parseBlacklist(data []byte) error {
	// Versuche als Array von Objekten zu parsen
	var entries []BlacklistEntry
	if err := json.Unmarshal(data, &entries); err == nil {
		p.processEntries(entries)
		return nil
	}

	// Versuche als Array von Strings zu parsen
	var stringEntries []string
	if err := json.Unmarshal(data, &stringEntries); err == nil {
		var converted []BlacklistEntry
		for _, ip := range stringEntries {
			converted = append(converted, BlacklistEntry{IP: ip})
		}
		p.processEntries(converted)
		return nil
	}

	// Versuche als Map zu parsen
	var mapEntries map[string]interface{}
	if err := json.Unmarshal(data, &mapEntries); err == nil {
		var converted []BlacklistEntry
		for ip := range mapEntries {
			converted = append(converted, BlacklistEntry{IP: ip})
		}
		p.processEntries(converted)
		return nil
	}

	return fmt.Errorf("konnte Blacklist nicht parsen")
}

// processEntries verarbeitet die geparsten Blacklist-Einträge
func (p *blacklistPlugin) processEntries(entries []BlacklistEntry) {
	newBlacklist := make(map[string]bool)
	var newCIDRList []*net.IPNet
	
	validIPCount := 0
	validCIDRCount := 0
	invalidCount := 0

	for _, entry := range entries {
		// Prüfe auf CIDR-Notation
		if strings.Contains(entry.IP, "/") {
			_, ipNet, err := net.ParseCIDR(entry.IP)
			if err == nil {
				newCIDRList = append(newCIDRList, ipNet)
				validCIDRCount++
				continue
			}
		}

		// Validiere als einfache IP-Adresse
		if ip := net.ParseIP(entry.IP); ip != nil {
			newBlacklist[entry.IP] = true
			validIPCount++
		} else {
			invalidCount++
			p.log.V(1).Info("Ungültige IP-Adresse in der Blacklist ignoriert", "ip", entry.IP)
		}
	}

	// Aktualisiere die Blacklist atomisch
	p.blacklistMutex.Lock()
	p.blacklist = newBlacklist
	p.blacklistCIDR = newCIDRList
	p.blacklistMutex.Unlock()

	p.log.Info("IP-Blacklist erfolgreich aktualisiert", 
		"validIPCount", validIPCount, 
		"validCIDRCount", validCIDRCount,
		"invalidCount", invalidCount,
		"totalEntries", len(entries))
}
