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
	var ipAddr string
	var virtualHost string
	var disconnect func(c.Component)

	// IP-Adresse und Verbindung aus Event extrahieren
	switch eventType := e.(type) {
	case *proxy.LoginEvent:
		if player := eventType.Player(); player != nil {
			ipAddr = extractIP(player.RemoteAddr())
			virtualHost = player.VirtualHost().String()
			disconnect = player.Disconnect
		}
	default:
		ipAddr = tryGetRemoteAddr(e)
		virtualHost = tryGetVirtualHost(e)
	}

	if ipAddr == "" {
		return
	}

	// Lokale und private IPs nicht blockieren
	ip := net.ParseIP(ipAddr)
	if ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		return
	}

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
		p.log.Info("VPN/Proxy-Verbindung blockiert",
			"ip", ipAddr,
			"virtualHost", virtualHost,
			"asn", result.Details.ASN,
			"asnOrg", result.Details.ASNOrg,
			"isp", result.Details.ISP)

		// Disconnect mit Nachricht
		if disconnect != nil {
			disconnect(&c.Text{Content: p.blockMessage})
			return
		}

		// Fallback für andere Event-Typen
		if tryDisconnect(e, &c.Text{Content: p.blockMessage}) {
			return
		}

		p.log.Info("Keine Disconnect-Methode verfügbar", "ip", ipAddr)
	}
}

// getStats gibt aktuelle Statistiken zurück
func (p *vpnProxyPlugin) getStats() connectionStats {
	p.statsMutex.RLock()
	defer p.statsMutex.RUnlock()
	return *p.stats
}

// logStats loggt aktuelle Statistiken
func (p *vpnProxyPlugin) logStats() {
	stats := p.getStats()
	uptime := time.Since(stats.StartTime)

	blockRate := float64(0)
	if stats.TotalConnections > 0 {
		blockRate = float64(stats.BlockedConnections) / float64(stats.TotalConnections) * 100
	}

	cacheSize := 0
	p.cacheMutex.RLock()
	cacheSize = len(p.cache)
	p.cacheMutex.RUnlock()

	p.log.Info("=== VPN/Proxy Detection Statistiken ===",
		"uptime", uptime.Round(time.Minute),
		"totalConnections", stats.TotalConnections,
		"allowedConnections", stats.AllowedConnections,
		"blockedConnections", stats.BlockedConnections,
		"blockRate", fmt.Sprintf("%.2f%%", blockRate),
		"apiRequests", stats.APIRequests,
		"cacheHits", stats.CacheHits,
		"apiErrors", stats.APIErrors,
		"cacheSize", cacheSize)
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
