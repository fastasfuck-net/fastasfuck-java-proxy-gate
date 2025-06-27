package antivpn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/robinbraemer/event"
	c "go.minekube.com/common/minecraft/component"
	"go.minekube.com/gate/pkg/edition/java/proxy"
	"go.minekube.com/gate/pkg/edition/java/lite/blacklist"
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
			asnListURLs: []string{
				"https://raw.githubusercontent.com/sysvar/lists_vpn/refs/heads/main/input/datacenter/ASN.txt",
				"https://raw.githubusercontent.com/fastasfuck-net/VPN-List/refs/heads/main/ASN.txt",
			},
			ispListURLs: []string{
				"https://raw.githubusercontent.com/fastasfuck-net/VPN-List/refs/heads/main/ISP.txt",
			},
			ipListURL: "https://raw.githubusercontent.com/fastasfuck-net/VPN-List/refs/heads/main/IP.txt",
			
			updateInterval:    5 * time.Minute,  // Listen-Updates
			blockMessage:      "VPN/Proxy connections are not allowed on this server\nPlease disconnect from your VPN/Proxy and try again",
			enabled:           true,
			
			// Logging-Konfiguration
			logAllConnections:    true,  // Alle Verbindungen loggen
			logBlockedOnly:       false, // Nur blockierte Verbindungen loggen
			logDetailedAnalysis:  true,  // Detaillierte Analyse-Ergebnisse loggen
			logConnectionStats:   true,  // Verbindungsstatistiken loggen
			
			// Interne Maps
			asnRegexList:    make([]*regexp.Regexp, 0),
			ispRegexList:    make([]*regexp.Regexp, 0),
			blockedIPs:      make(map[string]bool),
			whoisCache:      make(map[string]*whoisResult),
			activeConnections: make(map[string]net.Conn),
			
			// Statistiken initialisieren
			stats: &connectionStats{
				UniqueIPs:         make(map[string]bool),
				RecentConnections: make([]connectionLog, 0),
				TopASNs:          make(map[int]uint64),
				TopISPs:          make(map[string]uint64),
			},
			statsStartTime: time.Now(),
		}

		if !plugin.enabled {
			log.Info("VPN/Proxy Detection Plugin ist deaktiviert.")
			return nil
		}

		// Initialisiere lokale Blacklist-Dateien
		err := blacklist.InitBlacklist("./ip_blacklist.json", "./route_blacklist.json")
		if err != nil {
			log.Error(err, "Fehler beim Initialisieren der lokalen Blacklists")
		}

		// Starte den Update-Prozess im Hintergrund
		go plugin.startListUpdater(ctx)
		
		// Starte Statistik-Logger wenn aktiviert
		if plugin.logConnectionStats {
			go plugin.startStatsLogger(ctx)
		}

		// Event-Handler registrieren - Diese werden ZUERST ausgeführt
		event.Subscribe(p.Event(), 0, func(e event.Event) {
			plugin.handleEvent(e)
		})

		// Registriere eine einfache IP-Check-Funktion für Gate Lite (immer false, da wir Events verwenden)
		blacklist.RegisterIPCheckFunc(func(ipAddr string) bool {
			// Wir lassen das Blacklist-System passieren und handhaben VPN/Proxy über Events
			return false
		})

		log.Info("VPN/Proxy Detection Plugin erfolgreich initialisiert!",
			"asnListURLs", len(plugin.asnListURLs),
			"ispListURLs", len(plugin.ispListURLs),
			"updateInterval", plugin.updateInterval)
		return nil
	},
}

type vpnProxyPlugin struct {
	log            logr.Logger
	
	// Konfiguration
	asnListURLs         []string
	ispListURLs         []string
	ipListURL           string
	updateInterval      time.Duration
	blockMessage        string
	enabled             bool
	
	// Logging-Konfiguration
	logAllConnections   bool
	logBlockedOnly      bool
	logDetailedAnalysis bool
	logConnectionStats  bool
	
	// Listen und Caches
	asnRegexList   []*regexp.Regexp
	ispRegexList   []*regexp.Regexp
	blockedIPs     map[string]bool
	whoisCache     map[string]*whoisResult
	listMutex      sync.RWMutex
	cacheMutex     sync.RWMutex
	
	// Statistiken
	stats          *connectionStats
	statsMutex     sync.RWMutex
	statsStartTime time.Time
	
	// Aktive Verbindungen für Disconnect-Nachrichten
	activeConnections map[string]net.Conn
	connMutex        sync.RWMutex
}

type whoisResult struct {
	ISP       string
	ASN       int
	ASNOrg    string
	CacheTime time.Time
}

// Verbindungsstatistiken
type connectionStats struct {
	TotalConnections    uint64
	BlockedConnections  uint64
	AllowedConnections  uint64
	VPNByASN           uint64
	VPNByISP           uint64
	VPNByIP            uint64
	WhoisLookups       uint64
	CacheHits          uint64
	UniqueIPs          map[string]bool
	RecentConnections  []connectionLog
	TopASNs            map[int]uint64
	TopISPs            map[string]uint64
}

// Einzelne Verbindungslog-Einträge
type connectionLog struct {
	Timestamp    time.Time
	IP           string
	VirtualHost  string
	IsBlocked    bool
	DetectionSource string
	ASN          int
	ASNOrg       string
	ISP          string
}

// isBlocked prüft, ob eine IP als VPN/Proxy erkannt wird
func (p *vpnProxyPlugin) isBlocked(ipAddr string) bool {
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

	// Prüfe verschiedene Erkennungsmethoden
	result := p.analyzeIP(ipAddr)
	
	if result.IsVPN {
		p.log.Info("VPN/Proxy erkannt", 
			"ip", ipAddr,
			"asnMatch", result.ASNMatch,
			"ispMatch", result.ISPMatch,
			"ipListed", result.IPListed,
			"asn", result.ASN,
			"isp", result.ISP)
		return true
	}

	return false
}

// sendDisconnectMessage sendet eine ordentliche Minecraft-Disconnect-Nachricht
func (p *vpnProxyPlugin) sendDisconnectMessage(conn net.Conn, message string) error {
	// JSON-Nachricht für Minecraft formatieren
	disconnectMsg := map[string]interface{}{
		"text": message,
		"color": "red",
	}
	
	jsonMsg, err := json.Marshal(disconnectMsg)
	if err != nil {
		return err
	}

	// Packet ID für Disconnect (in Login State = 0x00)
	packetID := byte(0x00)
	
	// JSON-String-Länge als VarInt
	jsonLen := len(jsonMsg)
	
	// Berechne Paket-Länge (Packet ID + String Length VarInt + String)
	packetLen := 1 + getVarIntSize(jsonLen) + jsonLen
	
	// Buffer für das komplette Paket
	buf := make([]byte, getVarIntSize(packetLen)+packetLen)
	offset := 0
	
	// Schreibe Paket-Länge als VarInt
	offset += writeVarInt(buf[offset:], packetLen)
	
	// Schreibe Packet ID
	buf[offset] = packetID
	offset++
	
	// Schreibe JSON-String-Länge als VarInt
	offset += writeVarInt(buf[offset:], jsonLen)
	
	// Schreibe JSON-String
	copy(buf[offset:], jsonMsg)
	
	// Sende das Paket
	_, err = conn.Write(buf)
	if err != nil {
		return err
	}
	
	// Kurz warten damit die Nachricht ankommt
	time.Sleep(100 * time.Millisecond)
	
	return nil
}

// Hilfsfunktionen für VarInt-Encoding
func getVarIntSize(value int) int {
	if value == 0 {
		return 1
	}
	size := 0
	for value > 0 {
		value >>= 7
		size++
	}
	return size
}

func writeVarInt(buf []byte, value int) int {
	written := 0
	for {
		if (value & 0x80) == 0 {
			buf[written] = byte(value)
			written++
			break
		}
		buf[written] = byte(value&0x7F | 0x80)
		written++
		value >>= 7
	}
	return written
}

// sendDisconnectToConnection sendet eine Disconnect-Nachricht direkt an eine Verbindung
func (p *vpnProxyPlugin) sendDisconnectToConnection(conn net.Conn, ipAddr string) {
	// Versuche eine ordentliche Minecraft-Disconnect-Nachricht zu senden
	if err := p.sendDisconnectMessage(conn, p.blockMessage); err != nil {
		p.log.V(1).Info("Fehler beim Senden der Disconnect-Nachricht", "ip", ipAddr, "error", err)
	}
	
	// Schließe die Verbindung nach kurzer Verzögerung
	time.AfterFunc(200*time.Millisecond, func() {
		conn.Close()
	})
}

// analyzeIP führt eine umfassende Analyse einer IP-Adresse durch
func (p *vpnProxyPlugin) analyzeIP(ipAddr string) *analysisResult {
	result := &analysisResult{
		IP: ipAddr,
	}

	// 1. Prüfe gegen IP-Liste
	p.listMutex.RLock()
	result.IPListed = p.blockedIPs[ipAddr]
	p.listMutex.RUnlock()

	if result.IPListed {
		result.DetectionSource = "IP-List"
	}

	// 2. WHOIS-Lookup für ASN und ISP-Daten
	whoisData := p.getWhoisData(ipAddr)
	if whoisData != nil {
		result.ISP = whoisData.ISP
		result.ASN = whoisData.ASN
		result.ASNOrg = whoisData.ASNOrg

		// 3. Prüfe ASN gegen Liste
		if whoisData.ASN > 0 {
			asnStr := fmt.Sprintf("AS%d", whoisData.ASN)
			p.listMutex.RLock()
			for _, regex := range p.asnRegexList {
				if regex.MatchString(asnStr) {
					result.ASNMatch = true
					result.DetectionSource = "ASN-WHOIS"
					break
				}
			}
			p.listMutex.RUnlock()
		}

		// 4. Prüfe ISP gegen Liste
		if !result.ISPMatch && whoisData.ISP != "" {
			p.listMutex.RLock()
			for _, regex := range p.ispRegexList {
				if regex.MatchString(whoisData.ISP) {
					result.ISPMatch = true
					result.DetectionSource = "ISP-WHOIS"
					break
				}
			}
			p.listMutex.RUnlock()
		}

		// 5. Prüfe ASN-Organisation gegen ISP-Liste
		if !result.ISPMatch && whoisData.ASNOrg != "" {
			p.listMutex.RLock()
			for _, regex := range p.ispRegexList {
				if regex.MatchString(whoisData.ASNOrg) {
					result.ISPMatch = true
					result.DetectionSource = "ISP-WHOIS"
					break
				}
			}
			p.listMutex.RUnlock()
		}
	}

	// Endergebnis: VPN/Proxy wenn eine der Methoden positiv ist
	result.IsVPN = result.IPListed || result.ASNMatch || result.ISPMatch

	return result
}

type analysisResult struct {
	IP              string
	IsVPN           bool
	IPListed        bool
	ASNMatch        bool
	ISPMatch        bool
	ASN             int
	ASNOrg          string
	ISP             string
	DetectionSource string
}

// getWhoisData holt WHOIS-Daten mit Caching
func (p *vpnProxyPlugin) getWhoisData(ipAddr string) *whoisResult {
	// Cache prüfen
	p.cacheMutex.RLock()
	if cached, exists := p.whoisCache[ipAddr]; exists {
		// Cache-Eintrag ist 1 Stunde gültig
		if time.Since(cached.CacheTime) < time.Hour {
			p.cacheMutex.RUnlock()
			
			// Cache-Hit zählen
			p.statsMutex.Lock()
			p.stats.CacheHits++
			p.statsMutex.Unlock()
			
			return cached
		}
	}
	p.cacheMutex.RUnlock()

	// Neue WHOIS-Abfrage
	result := p.performWhoisLookup(ipAddr)
	if result != nil {
		result.CacheTime = time.Now()
		
		// Cache aktualisieren
		p.cacheMutex.Lock()
		p.whoisCache[ipAddr] = result
		p.cacheMutex.Unlock()
	}

	return result
}

// performWhoisLookup führt eine WHOIS-Abfrage durch
func (p *vpnProxyPlugin) performWhoisLookup(ipAddr string) *whoisResult {
	// WHOIS-Lookup zählen
	p.statsMutex.Lock()
	p.stats.WhoisLookups++
	p.statsMutex.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Verwende ipapi.co als Service
	url := fmt.Sprintf("https://ipapi.co/%s/json/", ipAddr)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		p.log.V(1).Info("Fehler beim Erstellen der WHOIS-Anfrage", "ip", ipAddr, "error", err)
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		p.log.V(1).Info("Fehler bei der WHOIS-Abfrage", "ip", ipAddr, "error", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // Max 1MB
	if err != nil {
		return nil
	}

	// Parse JSON-Response
	var apiResult struct {
		ASN     string `json:"asn"`
		Org     string `json:"org"`
		ISP     string `json:"isp"`
		Company string `json:"company"`
	}

	if err := json.Unmarshal(body, &apiResult); err != nil {
		return nil
	}

	result := &whoisResult{
		ISP:    apiResult.ISP,
		ASNOrg: apiResult.Org,
	}

	// Parse ASN
	if apiResult.ASN != "" {
		asnStr := strings.TrimPrefix(apiResult.ASN, "AS")
		if asn, err := strconv.Atoi(asnStr); err == nil {
			result.ASN = asn
		}
	}

	// Fallback für ISP
	if result.ISP == "" {
		result.ISP = apiResult.Company
	}

	return result
}

// handleEvent verarbeitet Events und sendet ordentliche Disconnect-Nachrichten
func (p *vpnProxyPlugin) handleEvent(e event.Event) {
	var ipAddr string
	var virtualHost string
	var disconnect func(c.Component)
	var rawConn net.Conn

	// IP-Adresse und Verbindung aus Event extrahieren
	switch eventType := e.(type) {
	case *proxy.LoginEvent:
		if player := eventType.Player(); player != nil {
			ipAddr = extractIP(player.RemoteAddr())
			virtualHost = player.VirtualHost().String()
			disconnect = player.Disconnect
			
			// Versuche rohe Verbindung zu extrahieren für direkte Disconnect-Nachricht
			if connProvider, ok := player.(interface{ Conn() net.Conn }); ok {
				rawConn = connProvider.Conn()
			}
		}
	default:
		ipAddr = tryGetRemoteAddr(e)
		virtualHost = tryGetVirtualHost(e)
		rawConn = tryGetRawConnection(e)
	}

	if ipAddr == "" {
		return
	}

	// Führe Analyse durch
	result := p.analyzeIP(ipAddr)
	
	// Statistiken aktualisieren
	p.updateStats(ipAddr, virtualHost, result)

	// Logging basierend auf Konfiguration
	if p.logAllConnections || (p.logBlockedOnly && result.IsVPN) {
		if p.logDetailedAnalysis {
			p.log.Info("Verbindung analysiert",
				"ip", ipAddr,
				"virtualHost", virtualHost,
				"eventType", fmt.Sprintf("%T", e),
				"isVPN", result.IsVPN,
				"ipListed", result.IPListed,
				"asnMatch", result.ASNMatch,
				"ispMatch", result.ISPMatch,
				"asn", result.ASN,
				"asnOrg", result.ASNOrg,
				"isp", result.ISP,
				"detectionSource", result.DetectionSource)
		} else {
			p.log.Info("Verbindung",
				"ip", ipAddr,
				"virtualHost", virtualHost,
				"status", func() string {
					if result.IsVPN {
						return "BLOCKED"
					}
					return "ALLOWED"
				}())
		}
	}

	// VPN/Proxy-Prüfung und Blockierung mit ordentlicher Disconnect-Nachricht
	if result.IsVPN {
		p.log.Info("VPN/Proxy-Verbindung blockiert",
			"ip", ipAddr,
			"virtualHost", virtualHost,
			"reason", result.DetectionSource)

		// Methode 1: Verwende die Standard-Disconnect-Funktion wenn verfügbar
		if disconnect != nil {
			disconnect(&c.Text{Content: p.blockMessage})
			return
		}

		// Methode 2: Verwende tryDisconnect für andere Event-Typen
		if tryDisconnect(e, &c.Text{Content: p.blockMessage}) {
			return
		}

		// Methode 3: Fallback - Sende direkte Minecraft-Disconnect-Nachricht über rohe Verbindung
		if rawConn != nil {
			p.log.Info("Sende direkte Disconnect-Nachricht", "ip", ipAddr)
			if err := p.sendDisconnectMessage(rawConn, p.blockMessage); err != nil {
				p.log.Error(err, "Fehler beim Senden der Disconnect-Nachricht", "ip", ipAddr)
			}
			// Schließe Verbindung nach kurzer Verzögerung
			go func() {
				time.Sleep(200 * time.Millisecond)
				rawConn.Close()
			}()
		} else {
			p.log.Info("Keine Disconnect-Methode verfügbar, Verbindung wird stumm geschlossen", "ip", ipAddr)
		}
	}
}

// updateStats aktualisiert die Verbindungsstatistiken
func (p *vpnProxyPlugin) updateStats(ipAddr, virtualHost string, result *analysisResult) {
	p.statsMutex.Lock()
	defer p.statsMutex.Unlock()

	// Basis-Statistiken
	p.stats.TotalConnections++
	p.stats.UniqueIPs[ipAddr] = true

	if result.IsVPN {
		p.stats.BlockedConnections++
		
		// Detaillierte VPN-Erkennungsstatistiken
		if result.IPListed {
			p.stats.VPNByIP++
		}
		if result.ASNMatch {
			p.stats.VPNByASN++
		}
		if result.ISPMatch {
			p.stats.VPNByISP++
		}
	} else {
		p.stats.AllowedConnections++
	}

	// Top ASNs
	if result.ASN > 0 {
		p.stats.TopASNs[result.ASN]++
	}

	// Top ISPs
	if result.ISP != "" {
		p.stats.TopISPs[result.ISP]++
	} else if result.ASNOrg != "" {
		p.stats.TopISPs[result.ASNOrg]++
	}

	// Aktuelle Verbindungen (letzte 100)
	connectionEntry := connectionLog{
		Timestamp:       time.Now(),
		IP:              ipAddr,
		VirtualHost:     virtualHost,
		IsBlocked:       result.IsVPN,
		DetectionSource: result.DetectionSource,
		ASN:             result.ASN,
		ASNOrg:          result.ASNOrg,
		ISP:             result.ISP,
	}

	p.stats.RecentConnections = append(p.stats.RecentConnections, connectionEntry)
	
	// Begrenze auf letzte 100 Verbindungen
	if len(p.stats.RecentConnections) > 100 {
		p.stats.RecentConnections = p.stats.RecentConnections[1:]
	}
}

// startStatsLogger startet den regelmäßigen Statistik-Logger
func (p *vpnProxyPlugin) startStatsLogger(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute) // Alle 10 Minuten
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.logDetailedStats()
		case <-ctx.Done():
			p.log.Info("Statistik-Logger beendet")
			return
		}
	}
}

// logDetailedStats loggt detaillierte Statistiken
func (p *vpnProxyPlugin) logDetailedStats() {
	p.statsMutex.RLock()
	defer p.statsMutex.RUnlock()

	uptime := time.Since(p.statsStartTime)
	
	p.log.Info("=== VPN/Proxy Detection Statistiken ===",
		"uptime", uptime.Round(time.Minute),
		"totalConnections", p.stats.TotalConnections,
		"allowedConnections", p.stats.AllowedConnections,
		"blockedConnections", p.stats.BlockedConnections,
		"blockRate", fmt.Sprintf("%.2f%%", float64(p.stats.BlockedConnections)/float64(p.stats.TotalConnections)*100),
		"uniqueIPs", len(p.stats.UniqueIPs))

	p.log.Info("=== Erkennungsmethoden ===",
		"vpnByIP", p.stats.VPNByIP,
		"vpnByASN", p.stats.VPNByASN,
		"vpnByISP", p.stats.VPNByISP,
		"whoisLookups", p.stats.WhoisLookups,
		"cacheHits", p.stats.CacheHits)

	// Top 5 ASNs
	topASNs := p.getTopASNs(5)
	if len(topASNs) > 0 {
		p.log.Info("=== Top ASNs ===", "topASNs", topASNs)
	}

	// Top 5 ISPs
	topISPs := p.getTopISPs(5)
	if len(topISPs) > 0 {
		p.log.Info("=== Top ISPs ===", "topISPs", topISPs)
	}

	// Letzte 5 blockierte Verbindungen
	recentBlocked := p.getRecentBlocked(5)
	if len(recentBlocked) > 0 {
		p.log.Info("=== Letzte blockierte Verbindungen ===")
		for i, conn := range recentBlocked {
			p.log.Info(fmt.Sprintf("  %d.", i+1),
				"ip", conn.IP,
				"time", conn.Timestamp.Format("15:04:05"),
				"reason", conn.DetectionSource,
				"asn", conn.ASN,
				"org", conn.ASNOrg)
		}
	}
}

// getTopASNs gibt die Top-N ASNs zurück
func (p *vpnProxyPlugin) getTopASNs(n int) []string {
	type asnCount struct {
		ASN   int
		Count uint64
	}

	var asns []asnCount
	for asn, count := range p.stats.TopASNs {
		asns = append(asns, asnCount{ASN: asn, Count: count})
	}

	// Sortiere nach Count (absteigend)
	for i := 0; i < len(asns)-1; i++ {
		for j := i + 1; j < len(asns); j++ {
			if asns[i].Count < asns[j].Count {
				asns[i], asns[j] = asns[j], asns[i]
			}
		}
	}

	// Limitiere auf Top-N
	if len(asns) > n {
		asns = asns[:n]
	}

	var result []string
	for _, asnCount := range asns {
		result = append(result, fmt.Sprintf("AS%d (%d)", asnCount.ASN, asnCount.Count))
	}

	return result
}

// getTopISPs gibt die Top-N ISPs zurück
func (p *vpnProxyPlugin) getTopISPs(n int) []string {
	type ispCount struct {
		ISP   string
		Count uint64
	}

	var isps []ispCount
	for isp, count := range p.stats.TopISPs {
		isps = append(isps, ispCount{ISP: isp, Count: count})
	}

	// Sortiere nach Count (absteigend)
	for i := 0; i < len(isps)-1; i++ {
		for j := i + 1; j < len(isps); j++ {
			if isps[i].Count < isps[j].Count {
				isps[i], isps[j] = isps[j], isps[i]
			}
		}
	}

	// Limitiere auf Top-N
	if len(isps) > n {
		isps = isps[:n]
	}

	var result []string
	for _, ispCount := range isps {
		result = append(result, fmt.Sprintf("%s (%d)", ispCount.ISP, ispCount.Count))
	}

	return result
}

// getRecentBlocked gibt die letzten N blockierten Verbindungen zurück
func (p *vpnProxyPlugin) getRecentBlocked(n int) []connectionLog {
	var blocked []connectionLog
	
	// Sammle blockierte Verbindungen (rückwärts für neueste zuerst)
	for i := len(p.stats.RecentConnections) - 1; i >= 0 && len(blocked) < n; i-- {
		if p.stats.RecentConnections[i].IsBlocked {
			blocked = append(blocked, p.stats.RecentConnections[i])
		}
	}

	return blocked
}

// startListUpdater startet die regelmäßige Aktualisierung der Listen
func (p *vpnProxyPlugin) startListUpdater(ctx context.Context) {
	// Sofort beim Start aktualisieren
	if err := p.updateAllLists(); err != nil {
		p.log.Error(err, "Initialer Listen-Update fehlgeschlagen")
	}

	ticker := time.NewTicker(p.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := p.updateAllLists(); err != nil {
				p.log.Error(err, "Listen-Update fehlgeschlagen")
			}
		case <-ctx.Done():
			p.log.Info("Listen Updater beendet")
			return
		}
	}
}

// updateAllLists aktualisiert alle Listen
func (p *vpnProxyPlugin) updateAllLists() error {
	p.log.Info("Aktualisiere VPN/Proxy-Listen...")

	// ASN-Listen laden
	asnPatterns, err := p.loadTextLists(p.asnListURLs, "AS")
	if err != nil {
		p.log.Error(err, "Fehler beim Laden der ASN-Listen")
	}

	// ISP-Listen laden
	ispPatterns, err := p.loadTextLists(p.ispListURLs, "")
	if err != nil {
		p.log.Error(err, "Fehler beim Laden der ISP-Listen")
	}

	// IP-Liste laden
	ipList, err := p.loadIPList()
	if err != nil {
		p.log.Error(err, "Fehler beim Laden der IP-Liste")
	}

	// Regex-Listen erstellen
	asnRegexes := make([]*regexp.Regexp, 0, len(asnPatterns))
	for _, pattern := range asnPatterns {
		if regex := wildcardToRegex(pattern); regex != nil {
			asnRegexes = append(asnRegexes, regex)
		}
	}

	ispRegexes := make([]*regexp.Regexp, 0, len(ispPatterns))
	for _, pattern := range ispPatterns {
		if regex := wildcardToRegex(pattern); regex != nil {
			ispRegexes = append(ispRegexes, regex)
		}
	}

	// IP-Map erstellen
	ipMap := make(map[string]bool)
	for _, ip := range ipList {
		ipMap[ip] = true
	}

	// Atomisch aktualisieren
	p.listMutex.Lock()
	p.asnRegexList = asnRegexes
	p.ispRegexList = ispRegexes
	p.blockedIPs = ipMap
	p.listMutex.Unlock()

	p.log.Info("Listen erfolgreich aktualisiert",
		"asnPatterns", len(asnRegexes),
		"ispPatterns", len(ispRegexes),
		"blockedIPs", len(ipMap))

	return nil
}

// loadTextLists lädt Text-Listen von URLs
func (p *vpnProxyPlugin) loadTextLists(urls []string, prefix string) ([]string, error) {
	var allPatterns []string

	for _, url := range urls {
		patterns, err := p.loadTextFromURL(url, prefix)
		if err != nil {
			p.log.Error(err, "Fehler beim Laden der Liste", "url", url)
			continue
		}
		allPatterns = append(allPatterns, patterns...)
	}

	return allPatterns, nil
}

// loadTextFromURL lädt Text von einer URL
func (p *vpnProxyPlugin) loadTextFromURL(url, prefix string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "VPNProxyDetector/1.0")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // Max 10MB
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(body), "\n")
	var patterns []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Prüfe Prefix-Filter
		if prefix != "" {
			if !strings.HasPrefix(strings.ToUpper(line), prefix) {
				continue
			}
		}

		patterns = append(patterns, line)
	}

	return patterns, nil
}

// loadIPList lädt die IP-Liste
func (p *vpnProxyPlugin) loadIPList() ([]string, error) {
	ips, err := p.loadTextFromURL(p.ipListURL, "")
	if err != nil {
		return nil, err
	}

	// Validiere IPs
	var validIPs []string
	for _, ip := range ips {
		if net.ParseIP(ip) != nil {
			validIPs = append(validIPs, ip)
		}
	}

	return validIPs, nil
}

// wildcardToRegex konvertiert Wildcard-Pattern zu Regex
func wildcardToRegex(pattern string) *regexp.Regexp {
	// Escape spezielle Regex-Zeichen, außer *
	escaped := regexp.QuoteMeta(pattern)
	// Ersetze \* durch .*
	escaped = strings.ReplaceAll(escaped, "\\*", ".*")
	// Füge Anker hinzu
	regexPattern := "^" + escaped + "$"
	
	regex, err := regexp.Compile("(?i)" + regexPattern) // Case-insensitive
	if err != nil {
		return nil
	}
	return regex
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

func isPrivateIP(ip net.IP) bool {
	privateIPv4Blocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	}

	privateIPv6Blocks := []string{
		"fc00::/7",
		"fe80::/10",
		"::1/128",
	}

	if ip.To4() != nil {
		for _, block := range privateIPv4Blocks {
			_, cidr, err := net.ParseCIDR(block)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		}
	} else {
		for _, block := range privateIPv6Blocks {
			_, cidr, err := net.ParseCIDR(block)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		}
	}

	return false
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

func tryGetRawConnection(e interface{}) net.Conn {
	// Versuche, die rohe Netzwerkverbindung aus verschiedenen Event-Typen zu extrahieren
	
	// 1. Direkte Verbindung
	if conn, ok := e.(net.Conn); ok {
		return conn
	}
	
	// 2. Über Conn()-Methode
	type connProvider interface {
		Conn() net.Conn
	}
	if provider, ok := e.(connProvider); ok {
		return provider.Conn()
	}
	
	// 3. Über Connection()-Methode
	type connectionProvider interface {
		Connection() interface{ Conn() net.Conn }
	}
	if provider, ok := e.(connectionProvider); ok {
		if conn := provider.Connection(); conn != nil {
			return conn.Conn()
		}
	}
	
	// 4. Über InitialConnection()-Methode  
	type initialConnectionProvider interface {
		InitialConnection() interface{ Conn() net.Conn }
	}
	if provider, ok := e.(initialConnectionProvider); ok {
		if conn := provider.InitialConnection(); conn != nil {
			return conn.Conn()
		}
	}
	
	// 5. Über Player()-Methode
	type playerProvider interface {
		Player() interface{ Conn() net.Conn }
	}
	if provider, ok := e.(playerProvider); ok {
		if player := provider.Player(); player != nil {
			return player.Conn()
		}
	}
	
	return nil
}

func tryDisconnect(e interface{}, reason c.Component) bool {
	// 1. Versuche direkt die Disconnect-Methode aufzurufen
	type disconnector interface {
		Disconnect(c.Component)
	}
	if d, ok := e.(disconnector); ok {
		d.Disconnect(reason)
		return true
	}

	// 2. Versuche über Connection/InitialConnection
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

	// 3. Versuche über Player-Methode
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
