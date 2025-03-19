package joinnotifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	"go.minekube.com/gate/pkg/edition/java/proxy"
)

// Plugin ist ein Gate-Plugin, das bei jedem Spieler-Join im Lite-Mode eine
// vereinfachte API-Benachrichtigung senden soll.
var Plugin = proxy.Plugin{
	Name: "JoinNotifier",
	Init: func(ctx context.Context, p *proxy.Proxy) error {
		log := logr.FromContextOrDiscard(ctx)
		log.Info("Join Notifier Plugin wird initialisiert...")

		// Erstelle eine neue Instanz des Plugins
		plugin := &joinNotifierPlugin{
			log:        log,
			// HIER EINSTELLUNGEN ANPASSEN:
			apiURL:     "https://example.com/api/player-join", // URL der API
			timeout:    5 * time.Second,                      // Timeout für API-Anfragen
			enabled:    true,                                 // Plugin aktivieren/deaktivieren
			retryCount: 3,                                    // Anzahl der Wiederholungsversuche
			retryDelay: time.Second,                          // Verzögerung zwischen Wiederholungsversuchen
		}

		if !plugin.enabled {
			log.Info("Join Notifier Plugin ist deaktiviert.")
			return nil
		}

		log.Info("Join Notifier Plugin erfolgreich initialisiert!")
		log.Info("HINWEIS: Dieses Plugin erfordert eine externe Lösung für Gate Lite.")
		log.Info("Bitte verwenden Sie das externe Python- oder Bash-Script für die Loganalyse.")
		
		// Führe einen API-Test durch
		go plugin.testAPIConnection()

		return nil
	},
}

type joinNotifierPlugin struct {
	log         logr.Logger
	apiURL      string
	timeout     time.Duration
	enabled     bool
	retryCount  int
	retryDelay  time.Duration
}

// JoinNotification enthält die Daten, die an die API gesendet werden
type JoinNotification struct {
	PlayerName string    `json:"playerName"`
	PlayerUUID string    `json:"playerUUID,omitempty"`
	IPAddress  string    `json:"ipAddress"`
	JoinTime   time.Time `json:"joinTime"`
}

// sendNotification sendet eine Benachrichtigung an die API
func (p *joinNotifierPlugin) sendNotification(notification JoinNotification) {
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

	p.log.Error(lastError, "Alle Versuche, die API-Anfrage zu senden, sind fehlgeschlagen")
}

// doSendRequest führt die eigentliche HTTP-Anfrage durch
func (p *joinNotifierPlugin) doSendRequest(jsonData []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", p.apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("fehler beim Erstellen der HTTP-Anfrage: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "JoinNotifier-Plugin/1.0")

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

	p.log.Info("Join-Benachrichtigung erfolgreich gesendet")
	return nil
}

// testAPIConnection testet die API-Verbindung
func (p *joinNotifierPlugin) testAPIConnection() {
	time.Sleep(5 * time.Second) // Warte ein wenig, bis der Server vollständig gestartet ist
	
	p.log.Info("Teste API-Verbindung...")
	
	// Erstelle eine Test-Benachrichtigung
	testNotification := JoinNotification{
		PlayerName: "TestSpieler",
		PlayerUUID: "00000000-0000-0000-0000-000000000000",
		IPAddress:  "127.0.0.1",
		JoinTime:   time.Now(),
	}

	// Sende Testbenachrichtigung
	p.sendNotification(testNotification)
}
