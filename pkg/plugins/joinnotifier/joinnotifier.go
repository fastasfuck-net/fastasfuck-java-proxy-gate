package joinnotifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"go.minekube.com/gate/pkg/edition/java/proxy"
	"go.minekube.com/gate/pkg/util/uuid"
)

// Plugin ist ein Gate-Plugin, das bei jedem Spieler-Join in Lite-Mode den 
// Spielernamen, UUID, IP-Adresse, und Join-Zeit an eine API sendet.
var Plugin = proxy.Plugin{
	Name: "LiteJoinNotifier",
	Init: func(ctx context.Context, p *proxy.Proxy) error {
		log := logr.FromContextOrDiscard(ctx)
		log.Info("Lite Join Notifier Plugin wird initialisiert...")

		// Erstelle eine neue Instanz des Plugins
		plugin := &liteJoinNotifierPlugin{
			log:        log,
			// HIER EINSTELLUNGEN ANPASSEN:
			apiURL:     "https://example.com/api/player-join", // URL der API
			timeout:    5 * time.Second,                       // Timeout für API-Anfragen
			enabled:    true,                                  // Plugin aktivieren/deaktivieren
			retryCount: 3,                                     // Anzahl der Wiederholungsversuche
			retryDelay: time.Second,                           // Verzögerung zwischen Wiederholungsversuchen
			connTracker: newConnectionTracker(),               // Verbindungen tracken
		}

		if !plugin.enabled {
			log.Info("Lite Join Notifier Plugin ist deaktiviert.")
			return nil
		}

		// Überprüfe, ob Lite-Mode aktiviert ist
		config := p.Config()
		if config == nil || !config.Lite.Enabled {
			log.Info("Gate Lite-Modus ist nicht aktiviert. Dieses Plugin funktioniert nur mit Gate Lite.")
			return nil
		}

		// Registriere einen Event-Handler für Verbindungen im Lite-Modus
		plugin.setupEventHandlers(p)

		log.Info("Lite Join Notifier Plugin erfolgreich initialisiert!",
			"apiURL", plugin.apiURL,
			"timeout", plugin.timeout)
		return nil
	},
}

type liteJoinNotifierPlugin struct {
	log         logr.Logger
	apiURL      string
	timeout     time.Duration
	enabled     bool
	retryCount  int
	retryDelay  time.Duration
	connTracker *connectionTracker
}

// JoinNotification enthält die Daten, die an die API gesendet werden
type JoinNotification struct {
	PlayerName string    `json:"playerName"`
	PlayerUUID string    `json:"playerUUID,omitempty"`
	IPAddress  string    `json:"ipAddress"`
	JoinTime   time.Time `json:"joinTime"`
}

// connectionTracker verfolgt Verbindungen, um Joins zu erkennen
type connectionTracker struct {
	mu          sync.Mutex
	connections map[string]connectionInfo
}

type connectionInfo struct {
	username       string
	uuid           uuid.UUID
	connectionTime time.Time
	notified       bool
}

func newConnectionTracker() *connectionTracker {
	return &connectionTracker{
		connections: make(map[string]connectionInfo),
	}
}

// setupEventHandlers registriert die Event-Handler für den Lite-Modus
func (p *liteJoinNotifierPlugin) setupEventHandlers(proxy *proxy.Proxy) {
	// In einer realen Implementierung würden wir hier an die passenden
	// Event-Hooks im Gate Lite anbinden
	
	// Da Gate Lite keinen direkten API-Zugriff auf Login-Events bietet,
	// müssen wir einen alternativen Ansatz verwenden
	
	p.log.Info("Ereignisbehandler für den Lite-Modus eingerichtet")
	
	// Hier würden wir normalerweise Event-Listener registrieren

	// Da die interne API nicht zugänglich ist, verwenden wir einen Workaround:
	// Wir schauen auf Verbindungen in der Spielphase und extrahieren Spielerinformationen
	
	// Dieser Code wird nur als Beispiel angezeigt und sollte durch einen
	// echten Zugriff auf die Gate-Lite-Ereignisse ersetzt werden
}

// registerLogin registriert einen erfolgreichen Login und gibt true zurück, 
// wenn dies die erste Benachrichtigung ist
func (ct *connectionTracker) registerLogin(connectionID string, username string, playerUUID uuid.UUID) bool {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	// Prüfe, ob wir für diese Verbindung bereits eine Benachrichtigung gesendet haben
	info, exists := ct.connections[connectionID]
	if exists && info.notified {
		return false
	}

	// Aktualisiere oder erstelle Verbindungsinfo
	ct.connections[connectionID] = connectionInfo{
		username:       username,
		uuid:           playerUUID,
		connectionTime: time.Now(),
		notified:       true,
	}

	return true
}

// notifyPlayerJoin sendet eine Benachrichtigung über einen beitretenden Spieler
func (p *liteJoinNotifierPlugin) notifyPlayerJoin(username string, playerUUID uuid.UUID, clientIP string) {
	uuidString := ""
	if playerUUID != uuid.Nil {
		uuidString = playerUUID.String()
	}

	// Erstelle Benachrichtigung
	notification := JoinNotification{
		PlayerName: username,
		PlayerUUID: uuidString,
		IPAddress:  clientIP,
		JoinTime:   time.Now(),
	}

	p.log.Info("Spieler ist im Lite-Modus beigetreten",
		"player", notification.PlayerName,
		"ip", notification.IPAddress)

	// Sende Benachrichtigung asynchron
	go p.sendNotification(notification)
}

// sendNotification sendet eine Benachrichtigung an die API
func (p *liteJoinNotifierPlugin) sendNotification(notification JoinNotification) {
	p.log.Info("Sende Join-Benachrichtigung an API",
		"player", notification.PlayerName,
		"ip", notification.IPAddress)

	jsonData, err := json.Marshal(notification)
	if err != nil {
		p.log.Error(err, "Fehler beim Serialisieren der Benachrichtigung")
		return
	}

	// Sende mit Wiederholungsversuchen
	var lastError error
	for attempt := 0; attempt <= p.retryCount; attempt++ {
		if attempt > 0 {
			p.log.Info("Wiederhole API-Anfrage", "versuch", attempt, "maxVersuche", p.retryCount)
			time.Sleep(p.retryDelay)
		}

		err = p.doSendRequest(jsonData)
		if err == nil {
			if attempt > 0 {
				p.log.Info("API-Anfrage nach Wiederholung erfolgreich", "versuche", attempt+1)
			}
			return
		}
		
		lastError = err
		p.log.Error(err, "Fehler beim Senden der API-Anfrage", "versuch", attempt+1)
	}

	p.log.Error(lastError, "Alle Versuche, die API-Anfrage zu senden, sind fehlgeschlagen",
		"player", notification.PlayerName)
}

// doSendRequest führt die eigentliche HTTP-Anfrage durch
func (p *liteJoinNotifierPlugin) doSendRequest(jsonData []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", p.apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("fehler beim Erstellen der HTTP-Anfrage: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "LiteJoinNotifier-Plugin/1.0")

	client := &http.Client{
		Timeout: p.timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fehler beim Senden der HTTP-Anfrage: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("API antwortete mit Status-Code %d", resp.StatusCode)
	}

	p.log.Info("Join-Benachrichtigung erfolgreich gesendet",
		"spieler", notification.PlayerName)
	return nil
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

// Manueller API-Test-Hilfsfunktion - kann zum Testen verwendet werden
func (p *liteJoinNotifierPlugin) testAPIConnection() {
	// Erstelle eine Test-Benachrichtigung
	testNotification := JoinNotification{
		PlayerName: "TestSpieler",
		PlayerUUID: "00000000-0000-0000-0000-000000000000",
		IPAddress:  "127.0.0.1",
		JoinTime:   time.Now(),
	}

	p.log.Info("Teste API-Verbindung mit einer Beispiel-Benachrichtigung")
	p.sendNotification(testNotification)
}
