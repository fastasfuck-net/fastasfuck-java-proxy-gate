// Package ipblacklist implementiert eine IP-Blacklist für Gate
package ipblacklist

import (
	"context"
	"encoding/json"
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

		// Registriere verschiedene Event-Handler für verschiedene Ereignisse
		// Das sollte sicherstellen, dass wir den richtigen Event-Typ erwischen
		event.Subscribe(p.Event(), event.LowestPriority, plugin.handleEvent) // Generischer Handler für alle Events

		// Explizit wichtige Events für Verbindungen registrieren
		p.Event().Subscribe(&proxy.PreLoginEvent{}, plugin.handlePreLogin)
		p.Event().Subscribe(&proxy.LoginEvent{}, plugin.handleLogin)

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
}

// BlacklistEntry repräsentiert einen Eintrag in der Blacklist
type BlacklistEntry struct {
	IP string `json:"ip"`
}

// handleEvent ist ein generischer Handler, der auf alle Events reagiert
// und versucht, IP-Adressen aus allen möglichen Ereignissen zu extrahieren
func (p *blacklistPlugin) handleEvent(e event.Event) {
	// Zeige den genauen Event-Typ an, um zu debuggen
	p.log.V(3).Info("Event erhalten", "type", event.TypeOf(e))

	var ipAddr string
	var playerToDisconnect interface {
		Disconnect(reason interface{})
	}

	// Versuche, verschiedene Event-Typen zu erkennen
	switch evt := e.(type) {
	case *proxy.LoginEvent:
		if player := evt.Player(); player != nil {
			ipAddr = extractIP(player.RemoteAddr())
			playerToDisconnect = player
		}
	case *proxy.PreLoginEvent:
		if conn := evt.Connection(); conn != nil {
			ipAddr = extractIP(conn.RemoteAddr())
			// Für PreLoginEvent verwenden wir die Deny-Methode statt Disconnect
		}
	case *proxy.ServerConnectedEvent:
		if player := evt.Player(); player != nil {
			ipAddr = extractIP(player.RemoteAddr())
			playerToDisconnect = player
		}
	}

	// Wenn wir eine IP gefunden haben, prüfen wir, ob sie blockiert werden sollte
	if ipAddr != "" && p.isBlocked(ipAddr) {
		p.log.Info("Verbindung von geblockter IP erkannt", "ip", ipAddr, "eventType", event.TypeOf(e))
		
		if playerToDisconnect != nil {
			// Ablehnen der Verbindung mit einer Nachricht
			disconnectMessage := &c.Text{
				Content: p.blockMessage,
			}
			playerToDisconnect.Disconnect(disconnectMessage)
		}
	}
}

// handlePreLogin behandelt speziell PreLoginEvents
func (p *blacklistPlugin) handlePreLogin(e event.Event) {
	preLoginEvent, ok := e.(*proxy.PreLoginEvent)
	if !ok {
		return // Falscher Event-Typ
	}

	conn := preLoginEvent.Connection()
	if conn == nil {
		return
	}

	ipAddr := extractIP(conn.RemoteAddr())
	if ipAddr == "" {
		return
	}

	if p.isBlocked(ipAddr) {
		p.log.Info("Verbindung von geblockter IP im PreLogin abgelehnt", "ip", ipAddr)
		
		// In PreLogin müssen wir einen anderen Mechanismus verwenden
		disconnectMsg := &c.Text{Content: p.blockMessage}
		preLoginEvent.Deny(disconnectMsg)
	}
}

// handleLogin behandelt speziell LoginEvents
func (p *blacklistPlugin) handleLogin(e event.Event) {
	loginEvent, ok := e.(*proxy.LoginEvent)
	if !ok {
		return // Falscher Event-Typ
	}

	player := loginEvent.Player()
	if player == nil {
		return
	}

	ipAddr := extractIP(player.RemoteAddr())
	if ipAddr == "" {
		return
	}

	if p.isBlocked(ipAddr) {
		p.log.Info("Verbindung von geblockter IP im Login abgelehnt", "ip", ipAddr)
		
		disconnectMsg := &c.Text{Content: p.blockMessage}
		player.Disconnect(disconnectMsg)
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
	p.updateBlacklist()

	// Dann regelmäßig aktualisieren
	ticker := time.NewTicker(p.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.updateBlacklist()
		case <-ctx.Done():
			p.log.Info("Blacklist Updater beendet")
			return
		}
	}
}

// updateBlacklist lädt die aktuelle Blacklist von der konfigurierten URL
func (p *blacklistPlugin) updateBlacklist() {
	p.log.Info("Aktualisiere IP-Blacklist...", "url", p.blacklistURL)

	// HTTP-Anfrage an die Blacklist-URL mit Kontext und Timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", p.blacklistURL, nil)
	if err != nil {
		p.log.Error(err, "Fehler beim Erstellen der HTTP-Anfrage")
		return
	}

	// User-Agent setzen, um höflich zu sein
	req.Header.Set("User-Agent", "IPBlacklist-Plugin/1.0")

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		p.log.Error(err, "Fehler beim Abrufen der Blacklist")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		p.log.Error(nil, "Unerwarteter Status-Code beim Abrufen der Blacklist", "statusCode", resp.StatusCode)
		return
	}

	// Lese den Response-Body mit Größenbeschränkung
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // Max 10MB
	if err != nil {
		p.log.Error(err, "Fehler beim Lesen der Blacklist-Antwort")
		return
	}

	// Versuche verschiedene Formate zu parsen
	if err := p.parseBlacklist(body); err != nil {
		p.log.Error(err, "Fehler beim Parsen der Blacklist")
	}
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

	return nil
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
