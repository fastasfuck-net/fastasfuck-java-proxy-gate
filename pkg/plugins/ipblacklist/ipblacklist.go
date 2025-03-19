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
	"go.minekube.com/gate/pkg/edition/java/lite/blacklist"
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

		// Initialisiere lokale Blacklist-Dateien
		err := blacklist.InitBlacklist("./ip_blacklist.json", "./route_blacklist.json")
		if err != nil {
			log.Error(err, "Fehler beim Initialisieren der lokalen Blacklists")
			// Continue anyway - this is not fatal
		}

		// Starte den Update-Prozess im Hintergrund
		go plugin.startBlacklistUpdater(ctx)

		// Abonniere alle Events und filtre nach Typ
		event.Subscribe(p.Event(), 0, func(e event.Event) {
			// Versuchen, verschiedene Arten von Events zu verarbeiten
			plugin.handleEvent(e)
		})

		// Registriere die IP-Check-Funktion für Gate Lite
		blacklist.RegisterIPCheckFunc(plugin.isBlocked)

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

// isBlocked prüft, ob eine IP blockiert ist (für Gate Lite)
func (p *blacklistPlugin) isBlocked(ipAddr string) bool {
	if ipAddr == "" {
		return false
	}

	ip := net.ParseIP(ipAddr)
	if ip == nil {
		p.log.V(1).Info("Ungültige IP-Adresse", "ip", ipAddr)
		return false
	}

	// Lokale und private IPs nicht blockieren
	if ip.IsLoopback() || isPrivateIP(ip) {
		return false
	}

	p.blacklistMutex.RLock()
	defer p.blacklistMutex.RUnlock()

	// Prüfe exakte Übereinstimmung
	if p.blacklist[ipAddr] {
		p.log.Info("Verbindung von geblockter IP abgelehnt (Gate Lite)", "ip", ipAddr)
		return true
	}

	// Prüfe CIDR-Bereiche
	for _, cidr := range p.blacklistCIDR {
		if cidr.Contains(ip) {
			p.log.Info("Verbindung von geblockter CIDR-Range abgelehnt (Gate Lite)", "ip", ipAddr)
			return true
		}
	}

	return false
}

// handleEvent verarbeitet verschiedene Event-Typen
func (p *blacklistPlugin) handleEvent(e event.Event) {
	// Extrahieren von IP-Adresse und Abbruchmöglichkeit je nach Event-Typ
	var ipAddr string
	var virtualHost string
	var disconnect func(c.Component)

	// Typ des Events ermitteln und entsprechende Informationen extrahieren
	switch eventType := e.(type) {
	case *proxy.LoginEvent:
		if player := eventType.Player(); player != nil {
			ipAddr = extractIP(player.RemoteAddr())
			virtualHost = player.VirtualHost().String()
			disconnect = player.Disconnect
		}
	default:
		// Versuchen, die allgemeinen Schnittstellen-Methoden aufzurufen
		// über Reflection oder Typ-Assertion, wenn möglich
		
		// 1. Versuchen, ob das Event einen RemoteAddr()-Methode hat
		ipAddr = tryGetRemoteAddr(e)
		
		// 2. Versuchen, ob das Event einen VirtualHost()-Methode hat
		virtualHost = tryGetVirtualHost(e)
	}

	// Wenn keine IP extrahiert werden konnte, beende hier
	if ipAddr == "" {
		return
	}

	// IP-Adresse in der Konsole anzeigen
	p.log.Info("Verbindung", 
		"ip", ipAddr,
		"virtualHost", virtualHost,
		"eventType", fmt.Sprintf("%T", e))

	// Prüfe, ob die IP in der Blacklist ist
	if p.isBlocked(ipAddr) {
		p.log.Info("Verbindung von geblockter IP abgelehnt", 
			"ip", ipAddr,
			"virtualHost", virtualHost)

		// Wenn wir die Möglichkeit haben, die Verbindung zu trennen
		if disconnect != nil {
			disconnect(&c.Text{Content: p.blockMessage})
		} else {
			// Versuchen, disconnect über Reflection aufzurufen
			tryDisconnect(e, &c.Text{Content: p.blockMessage})
		}
	}
}

// tryGetRemoteAddr versucht, die RemoteAddr()-Methode eines beliebigen Events aufzurufen
func tryGetRemoteAddr(e interface{}) string {
	// Versuche verschiedene Methoden und Schnittstellen:
	// 1. Direkte Typumwandlung zu bekannten Schnittstellen
	type remoteAddressProvider interface {
		RemoteAddr() net.Addr
	}
	if provider, ok := e.(remoteAddressProvider); ok {
		return extractIP(provider.RemoteAddr())
	}

	// 2. Versuche, ob das Event eine Methode Connection() oder InitialConnection() hat
	type connectionProvider interface {
		Connection() interface{ RemoteAddr() net.Addr }
	}
	if provider, ok := e.(connectionProvider); ok {
		if conn := provider.Connection(); conn != nil {
			return extractIP(conn.RemoteAddr())
		}
	}

	type initialConnectionProvider interface {
		InitialConnection() interface{ RemoteAddr() net.Addr }
	}
	if provider, ok := e.(initialConnectionProvider); ok {
		if conn := provider.InitialConnection(); conn != nil {
			return extractIP(conn.RemoteAddr())
		}
	}

	// 3. Fallback: versuche, IP aus Event-Beschreibung zu extrahieren
	if stringer, ok := e.(fmt.Stringer); ok {
		desc := stringer.String()
		// Suche nach IP-Mustern in der Beschreibung
		return extractIPFromString(desc)
	}

	return ""
}

// tryGetVirtualHost versucht, die VirtualHost()-Methode eines beliebigen Events aufzurufen
func tryGetVirtualHost(e interface{}) string {
	// Versuche verschiedene Methoden und Schnittstellen
	type virtualHostProvider interface {
		VirtualHost() interface{ String() string }
	}
	if provider, ok := e.(virtualHostProvider); ok {
		if vh := provider.VirtualHost(); vh != nil {
			return vh.String()
		}
	}

	// Versuche andere Möglichkeiten, den virtuellen Host zu erhalten
	type connectionProvider interface {
		Connection() interface{
			VirtualHost() interface{ String() string }
		}
	}
	if provider, ok := e.(connectionProvider); ok {
		if conn := provider.Connection(); conn != nil {
			if vh := conn.VirtualHost(); vh != nil {
				return vh.String()
			}
		}
	}

	type initialConnectionProvider interface {
		InitialConnection() interface{
			VirtualHost() interface{ String() string }
		}
	}
	if provider, ok := e.(initialConnectionProvider); ok {
		if conn := provider.InitialConnection(); conn != nil {
			if vh := conn.VirtualHost(); vh != nil {
				return vh.String()
			}
		}
	}

	return "unbekannt"
}

// tryDisconnect versucht, die Disconnect()-Methode eines beliebigen Events aufzurufen
func tryDisconnect(e interface{}, reason c.Component) {
	// 1. Versuche direkt die Disconnect-Methode aufzurufen
	type disconnector interface {
		Disconnect(c.Component)
	}
	if d, ok := e.(disconnector); ok {
		d.Disconnect(reason)
		return
	}

	// 2. Versuche über Connection/InitialConnection
	type connectionProvider interface {
		Connection() interface{ Disconnect(c.Component) }
	}
	if provider, ok := e.(connectionProvider); ok {
		if conn := provider.Connection(); conn != nil {
			conn.Disconnect(reason)
			return
		}
	}

	type initialConnectionProvider interface {
		InitialConnection() interface{ Disconnect(c.Component) }
	}
	if provider, ok := e.(initialConnectionProvider); ok {
		if conn := provider.InitialConnection(); conn != nil {
			conn.Disconnect(reason)
			return
		}
	}

	// 3. Versuche über Player-Methode
	type playerProvider interface {
		Player() interface{ Disconnect(c.Component) }
	}
	if provider, ok := e.(playerProvider); ok {
		if player := provider.Player(); player != nil {
			player.Disconnect(reason)
			return
		}
	}
}

// extractIPFromString extrahiert eine IP-Adresse aus einem String
func extractIPFromString(s string) string {
	// Einfacher Ansatz: suche nach IP-ähnlichen Mustern
	// IPv4-Regex-Muster könnte hier verwendet werden
	
	// Suche nach "IP: x.x.x.x" oder ähnlichen Mustern
	parts := strings.Split(s, " ")
	for _, part := range parts {
		// Prüfe, ob es eine IP-Adresse sein könnte
		if ip := net.ParseIP(part); ip != nil {
			return ip.String()
		}
	}

	// Versuche, aus Mustern wie "1.2.3.4:5678" zu extrahieren
	for _, part := range parts {
		host, _, err := net.SplitHostPort(part)
		if err == nil && net.ParseIP(host) != nil {
			return host
		}
	}

	return ""
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
