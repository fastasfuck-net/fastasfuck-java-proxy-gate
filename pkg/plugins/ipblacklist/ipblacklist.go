package ipblacklist

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/robinbraemer/event"
	c "go.minekube.com/common/minecraft/component"
	"go.minekube.com/gate/pkg/edition/java/proxy"
)

// Plugin ist ein VPN/Proxy-Erkennungs-Plugin
var Plugin = proxy.Plugin{
	Name: "VPNProxyDetector",
	Init: func(ctx context.Context, p *proxy.Proxy) error {
		log := logr.FromContextOrDiscard(ctx)
		log.Info("VPN/Proxy Detection Plugin wird initialisiert...")

		// Erstelle eine neue Instanz des Plugins
		plugin := &vpnProxyPlugin{
			log: log,
			
			// HIER EINSTELLUNGEN ANPASSEN:
			apiURL:              "https://vpn.otp.cx/check",
			blockMessage:        "VPN/Proxy connections are not allowed on this server\nPlease disconnect from your VPN/Proxy and try again",
			enabled:             true,
			requestTimeout:      5 * time.Second,
			cacheTimeout:        30 * time.Minute,
			
			// Logging-Konfiguration
			logAllConnections:   true,  // Alle Verbindungen loggen
			logBlockedOnly:      false, // Nur blockierte Verbindungen loggen
			
			// Cache initialisieren
			cache: make(map[string]*cacheEntry),
			
			// Statistiken initialisieren
			stats: &connectionStats{
				StartTime: time.Now(),
			},
		}

		if !plugin.enabled {
			log.Info("VPN/Proxy Detection Plugin ist deaktiviert.")
			return nil
		}

		// Event-Handler registrieren
		event.Subscribe(p.Event(), 0, func(e event.Event) {
			plugin.handleEvent(e)
		})

		log.Info("VPN/Proxy Detection Plugin erfolgreich initialisiert!")
		
		// Debug: Test API-Verbindung
		go func() {
			time.Sleep(2 * time.Second)
			testResult, err := plugin.checkIP("8.8.8.8")
			if err != nil {
				log.Error(err, "API-Test fehlgeschlagen")
			} else {
				log.Info("API-Test erfolgreich", "result", testResult)
			}
		}()
		
		return nil
	},
}

type vpnProxyPlugin struct {
	log            logr.Logger
	
	// Konfiguration
	apiURL             string
	blockMessage       string
	enabled            bool
	requestTimeout     time.Duration
	cacheTimeout       time.Duration
	
	// Logging-Konfiguration
	logAllConnections  bool
	logBlockedOnly     bool
	
	// Cache
	cache              map[string]*cacheEntry
	cacheMutex         sync.RWMutex
	
	// Statistiken
	stats              *connectionStats
	statsMutex         sync.RWMutex
}

type cacheEntry struct {
	Result    *apiResponse
	Timestamp time.Time
}

type apiResponse struct {
	IP      string     `json:"ip"`
	IsVPN   bool       `json:"isVPN"`
	Details apiDetails `json:"details"`
}

type apiDetails struct {
	ASN       string `json:"asn"`
	ASNOrg    string `json:"asnOrg"`
	ISP       string `json:"isp"`
	Hostname  string `json:"hostname"`
	ASNMatch  bool   `json:"asnMatch"`
	ISPMatch  bool   `json:"ispMatch"`
	IPListed  bool   `json:"ipListed"`
}

type connectionStats struct {
	StartTime           time.Time
	TotalConnections    uint64
	AllowedConnections  uint64
	BlockedConnections  uint64
	APIRequests         uint64
	CacheHits          uint64
	APIErrors          uint64
}

// checkIP prüft eine IP-Adresse über die API
func (p *vpnProxyPlugin) checkIP(ipAddr string) (*apiResponse, error) {
	// Prüfe Cache zuerst
	if cached := p.getCachedResult(ipAddr); cached != nil {
		p.statsMutex.Lock()
		p.stats.CacheHits++
		p.statsMutex.Unlock()
		return cached, nil
	}

	// API-Request
	p.statsMutex.Lock()
	p.stats.APIRequests++
	p.statsMutex.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), p.requestTimeout)
	defer cancel()

	url := fmt.Sprintf("%s?ip=%s", p.apiURL, ipAddr)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		p.statsMutex.Lock()
		p.stats.APIErrors++
		p.statsMutex.Unlock()
		return nil, err
	}

	client := &http.Client{Timeout: p.requestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		p.statsMutex.Lock()
		p.stats.APIErrors++
		p.statsMutex.Unlock()
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		p.statsMutex.Lock()
		p.stats.APIErrors++
		p.statsMutex.Unlock()
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // Max 1MB
	if err != nil {
		p.statsMutex.Lock()
		p.stats.APIErrors++
		p.statsMutex.Unlock()
		return nil, err
	}

	var apiResp apiResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		p.statsMutex.Lock()
		p.stats.APIErrors++
		p.statsMutex.Unlock()
		return nil, err
	}

	// In Cache speichern
	p.setCachedResult(ipAddr, &apiResp)

	return &apiResp, nil
}

// getCachedResult holt ein Ergebnis aus dem Cache
func (p *vpnProxyPlugin) getCachedResult(ipAddr string) *apiResponse {
	p.cacheMutex.RLock()
	defer p.cacheMutex.RUnlock()

	if entry, exists := p.cache[ipAddr]; exists {
		if time.Since(entry.Timestamp) < p.cacheTimeout {
			return entry.Result
		}
		// Cache-Eintrag ist abgelaufen, wird beim nächsten setCachedResult aufgeräumt
	}

	return nil
}

// setCachedResult speichert ein Ergebnis im Cache
func (p *vpnProxyPlugin) setCachedResult(ipAddr string, result *apiResponse) {
	p.cacheMutex.Lock()
	defer p.cacheMutex.Unlock()

	// Speichere neuen Eintrag
	p.cache[ipAddr] = &cacheEntry{
		Result:    result,
		Timestamp: time.Now(),
	}

	// Cache-Cleanup (entferne abgelaufene Einträge)
	now := time.Now()
	for ip, entry := range p.cache {
		if now.Sub(entry.Timestamp) > p.cacheTimeout {
			delete(p.cache, ip)
		}
	}
}

// handleEvent verarbeitet Events
func (p *vpnProxyPlugin) handleEvent(e event.Event) {
	// Debug: Alle Events loggen
	p.log.Info("Event empfangen", "eventType", fmt.Sprintf("%T", e))
	
	var ipAddr string
	var virtualHost string
	var disconnect func(c.Component)

	// IP-Adresse und Verbindung aus Event extrahieren
	switch eventType := e.(type) {
	case *proxy.LoginEvent:
		p.log.Info("LoginEvent erkannt")
		if player := eventType.Player(); player != nil {
			ipAddr = extractIP(player.RemoteAddr())
			virtualHost = player.VirtualHost().String()
			disconnect = player.Disconnect
			p.log.Info("Player-Daten extrahiert", "ip", ipAddr, "virtualHost", virtualHost)
		} else {
			p.log.Info("Player ist nil")
		}
	default:
		p.log.Info("Anderer Event-Typ, versuche IP zu extrahieren")
		ipAddr = tryGetRemoteAddr(e)
		virtualHost = tryGetVirtualHost(e)
		p.log.Info("Event-Daten extrahiert", "ip", ipAddr, "virtualHost", virtualHost)
	}

	if ipAddr == "" {
		p.log.Info("Keine IP-Adresse gefunden, Event wird ignoriert")
		return
	}

	// Lokale und private IPs nicht blockieren
	ip := net.ParseIP(ipAddr)
	if ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		p.log.Info("Lokale/private IP erkannt, wird nicht geprüft", "ip", ipAddr)
		return
	}

	p.log.Info("IP-Adresse wird geprüft", "ip", ipAddr)

	// Statistiken aktualisieren
	p.statsMutex.Lock()
	p.stats.TotalConnections++
	p.statsMutex.Unlock()

	// API-Check durchführen
	result, err := p.checkIP(ipAddr)
	if err != nil {
		p.log.Error(err, "Fehler bei VPN-Check", "ip", ipAddr)
		// Bei API-Fehler Verbindung erlauben
		p.statsMutex.Lock()
		p.stats.AllowedConnections++
		p.statsMutex.Unlock()
		return
	}

	p.log.Info("API-Check abgeschlossen", "ip", ipAddr, "isVPN", result.IsVPN)

	// Statistiken aktualisieren
	if result.IsVPN {
		p.statsMutex.Lock()
		p.stats.BlockedConnections++
		p.statsMutex.Unlock()
	} else {
		p.statsMutex.Lock()
		p.stats.AllowedConnections++
		p.statsMutex.Unlock()
	}

	// Logging basierend auf Konfiguration
	if p.logAllConnections || (p.logBlockedOnly && result.IsVPN) {
		detectionMethod := ""
		if result.Details.IPListed {
			detectionMethod = "IP-Listed"
		} else if result.Details.ASNMatch {
			detectionMethod = "ASN-Match"
		} else if result.Details.ISPMatch {
			detectionMethod = "ISP-Match"
		}

		p.log.Info("Verbindung analysiert",
			"ip", ipAddr,
			"virtualHost", virtualHost,
			"isVPN", result.IsVPN,
			"asn", result.Details.ASN,
			"asnOrg", result.Details.ASNOrg,
			"isp", result.Details.ISP,
			"hostname", result.Details.Hostname,
			"detection", detectionMethod,
			"status", func() string {
				if result.IsVPN {
					return "BLOCKED"
				}
				return "ALLOWED"
			}())
	}

	// VPN/Proxy blockieren
	if result.IsVPN {
		p.log.Info("VPN/Proxy-Verbindung wird blockiert",
			"ip", ipAddr,
			"virtualHost", virtualHost,
			"asn", result.Details.ASN,
			"asnOrg", result.Details.ASNOrg,
			"isp", result.Details.ISP)

		// Disconnect mit Nachricht
		if disconnect != nil {
			p.log.Info("Verwende direkte Disconnect-Funktion")
			disconnect(&c.Text{Content: p.blockMessage})
			return
		}

		// Fallback für andere Event-Typen
		p.log.Info("Versuche Fallback-Disconnect")
		if tryDisconnect(e, &c.Text{Content: p.blockMessage}) {
			p.log.Info("Fallback-Disconnect erfolgreich")
			return
		}

		p.log.Info("Keine Disconnect-Methode verfügbar", "ip", ipAddr)
	} else {
		p.log.Info("Verbindung erlaubt", "ip", ipAddr)
	}
}



// Hilfsfunktionen

func extractIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}

	var ipStr string
	switch v := addr.(type) {
	case *net.TCPAddr:
		ipStr = v.IP.String()
	case *net.UDPAddr:
		ipStr = v.IP.String()
	default:
		addrStr := addr.String()
		host, _, err := net.SplitHostPort(addrStr)
		if err != nil {
			ipStr = addrStr
		} else {
			ipStr = host
		}
	}

	if net.ParseIP(ipStr) != nil {
		return ipStr
	}
	return ""
}

func tryGetRemoteAddr(e interface{}) string {
	type remoteAddressProvider interface {
		RemoteAddr() net.Addr
	}
	if provider, ok := e.(remoteAddressProvider); ok {
		return extractIP(provider.RemoteAddr())
	}

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

	return ""
}

func tryGetVirtualHost(e interface{}) string {
	type virtualHostProvider interface {
		VirtualHost() interface{ String() string }
	}
	if provider, ok := e.(virtualHostProvider); ok {
		if vh := provider.VirtualHost(); vh != nil {
			return vh.String()
		}
	}

	return "unbekannt"
}

func tryDisconnect(e interface{}, reason c.Component) bool {
	type disconnector interface {
		Disconnect(c.Component)
	}
	if d, ok := e.(disconnector); ok {
		d.Disconnect(reason)
		return true
	}

	type connectionProvider interface {
		Connection() interface{ Disconnect(c.Component) }
	}
	if provider, ok := e.(connectionProvider); ok {
		if conn := provider.Connection(); conn != nil {
			conn.Disconnect(reason)
			return true
		}
	}

	type initialConnectionProvider interface {
		InitialConnection() interface{ Disconnect(c.Component) }
	}
	if provider, ok := e.(initialConnectionProvider); ok {
		if conn := provider.InitialConnection(); conn != nil {
			conn.Disconnect(reason)
			return true
		}
	}

	type playerProvider interface {
		Player() interface{ Disconnect(c.Component) }
	}
	if provider, ok := e.(playerProvider); ok {
		if player := provider.Player(); player != nil {
			player.Disconnect(reason)
			return true
		}
	}
	
	return false
}
