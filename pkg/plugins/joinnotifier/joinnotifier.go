package joinnotifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	"github.com/robinbraemer/event"
	"go.minekube.com/gate/pkg/edition/java/proxy"
)

// Plugin ist ein Gate-Plugin, das bei jedem Spieler-Join den Spielernamen
// und die IP-Adresse an eine API sendet.
var Plugin = proxy.Plugin{
	Name: "JoinNotifier",
	Init: func(ctx context.Context, p *proxy.Proxy) error {
		log := logr.FromContextOrDiscard(ctx)
		log.Info("Join Notifier Plugin wird initialisiert...")

		// Erstelle eine neue Instanz des Plugins
		plugin := &joinNotifierPlugin{
			log:         log,
			// HIER EINSTELLUNGEN ANPASSEN:
			apiURL:      "https://example.com/api/player-join",  // URL der API
			timeout:     5 * time.Second,                        // Timeout für API-Anfragen
			enabled:     true,                                   // Plugin aktivieren/deaktivieren
			retryCount:  3,                                      // Anzahl der Wiederholungsversuche
			retryDelay:  time.Second,                            // Verzögerung zwischen Wiederholungsversuchen
		}

		if !plugin.enabled {
			log.Info("Join Notifier Plugin ist deaktiviert.")
			return nil
		}

		// Auf Login-Events hören
		event.Subscribe(p.Event(), plugin.eventPriority(), func(e event.Event) {
			// Versuche, das Event als LoginEvent zu behandeln
			if loginEvent, ok := e.(*proxy.LoginEvent); ok {
				plugin.handlePlayerJoin(loginEvent)
			}
		})

		log.Info("Join Notifier Plugin erfolgreich initialisiert!",
			"apiURL", plugin.apiURL,
			"timeout", plugin.timeout)
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

// API Request und Response Strukturen
type JoinNotification struct {
	PlayerName  string    `json:"playerName"`
	PlayerUUID  string    `json:"playerUUID,omitempty"`
	IPAddress   string    `json:"ipAddress"`
	ServerName  string    `json:"serverName,omitempty"`
	JoinTime    time.Time `json:"joinTime"`
	VirtualHost string    `json:"virtualHost,omitempty"`
}

// eventPriority gibt die Priorität zurück, mit der das Plugin auf Events hört
func (p *joinNotifierPlugin) eventPriority() int {
	return 0 // Standard-Priorität
}

// handlePlayerJoin behandelt den Login eines Spielers
func (p *joinNotifierPlugin) handlePlayerJoin(e *proxy.LoginEvent) {
	player := e.Player()
	if player == nil {
		p.log.Error(nil, "Player ist nil bei Login-Event")
		return
	}

	// Extrahiere die IP-Adresse
	var ipAddr string
	if remoteAddr := player.RemoteAddr(); remoteAddr != nil {
		host, _, err := net.SplitHostPort(remoteAddr.String())
		if err == nil {
			ipAddr = host
		} else {
			ipAddr = remoteAddr.String()
		}
	}

	// Bereite die Benachrichtigung vor
	notification := JoinNotification{
		PlayerName:  player.Username(),
		PlayerUUID:  player.ID().String(),
		IPAddress:   ipAddr,
		ServerName:  "Gate Proxy", // Kann angepasst werden
		JoinTime:    time.Now(),
		VirtualHost: player.VirtualHost().String(),
	}

	// Sende die Benachrichtigung asynchron, um den Spieler-Login nicht zu verzögern
	go p.sendNotification(notification)
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
			p.log.Info("Wiederhole API-Anfrage", "versuch", attempt, "vonMax", p.retryCount)
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

	p.log.Info("Join-Benachrichtigung erfolgreich gesendet", 
		"player", string(jsonData))
	return nil
}
