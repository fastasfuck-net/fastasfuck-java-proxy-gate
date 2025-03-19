package joinnotifier

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/robinbraemer/event"
	"go.minekube.com/common/minecraft/component"
	"go.minekube.com/common/minecraft/component/codec/legacy"
	"go.minekube.com/gate/pkg/edition/java/proxy"
	"go.minekube.com/gate/pkg/util/uuid"
)

// Plugin ist ein Gate-Plugin, das Spielerbeitritte im Chat anzeigt
var Plugin = proxy.Plugin{
	Name: "JoinNotifier",
	Init: func(ctx context.Context, p *proxy.Proxy) error {
		log := logr.FromContextOrDiscard(ctx)
		log.Info("Join Notifier Plugin wird initialisiert...")

		// Erstelle eine neue Instanz des Plugins
		plugin := &joinNotifierPlugin{
			log:         log,
			proxy:       p,
			playerCache: make(map[uuid.UUID]time.Time),
			// HIER EINSTELLUNGEN ANPASSEN:
			enabled:     true,
			joinMessage: "&8[&aGatelite&8] &eDer Spieler &b%s &ehat den Server betreten!",
			quitMessage: "&8[&aGatelite&8] &eDer Spieler &b%s &ehat den Server verlassen!",
			checkInterval: 2 * time.Second,
		}

		if !plugin.enabled {
			log.Info("Join Notifier Plugin ist deaktiviert.")
			return nil
		}

		// Da wir keine direkten Join/Leave-Events haben, versuchen wir alle verfügbaren Events
		_ = event.Subscribe(p.Event(), 0, plugin.handlePostLogin)
		_ = event.Subscribe(p.Event(), 0, plugin.handleDisconnect)
		
		// Starte einen Hintergrundprozess zur Erkennung von Spieleränderungen
		go plugin.checkPlayersRegularly(ctx)

		log.Info("Join Notifier Plugin erfolgreich initialisiert!")
		
		return nil
	},
}

type joinNotifierPlugin struct {
	log           logr.Logger
	proxy         *proxy.Proxy
	enabled       bool
	joinMessage   string
	quitMessage   string
	checkInterval time.Duration
	
	mu           sync.Mutex
	playerCache  map[uuid.UUID]time.Time // Spieler-Cache, um Änderungen zu erkennen
}

// Wandelt einen String in eine component.Component um
func textComponent(message string) component.Component {
	legacyParser := &legacy.Legacy{}
	comp, err := legacyParser.Unmarshal([]byte(message))
	if err != nil {
		return &component.Text{Content: message}
	}
	return comp
}

// Handler für PostLoginEvent (falls verfügbar)
func (p *joinNotifierPlugin) handlePostLogin(e *proxy.PostLoginEvent) {
	player := e.Player()
	if player == nil {
		return
	}

	playerName := player.Username()
	playerID := player.ID()
	
	p.mu.Lock()
	_, exists := p.playerCache[playerID]
	p.playerCache[playerID] = time.Now()
	p.mu.Unlock()
	
	if !exists {
		p.log.Info("Spieler hat den Server betreten (Event)", "player", playerName)
		message := fmt.Sprintf(p.joinMessage, playerName)
		p.broadcastMessage(message)
	}
}

// Handler für DisconnectEvent (falls verfügbar)
func (p *joinNotifierPlugin) handleDisconnect(e *proxy.DisconnectEvent) {
	player := e.Player()
	if player == nil {
		return
	}

	playerName := player.Username()
	playerID := player.ID()
	
	p.mu.Lock()
	delete(p.playerCache, playerID)
	p.mu.Unlock()
	
	p.log.Info("Spieler hat den Server verlassen (Event)", "player", playerName)
	message := fmt.Sprintf(p.quitMessage, playerName)
	p.broadcastMessage(message)
}

// Regelmäßiger Check zur Erkennung von Spieleränderungen
func (p *joinNotifierPlugin) checkPlayersRegularly(ctx context.Context) {
	ticker := time.NewTicker(p.checkInterval)
	defer ticker.Stop()

	var lastPlayers = make(map[uuid.UUID]string)
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			currentPlayers := make(map[uuid.UUID]string)
			
			// Aktuelle Spielerliste erfassen
			for _, player := range p.proxy.Players() {
				currentPlayers[player.ID()] = player.Username()
			}
			
			// Prüfen, ob neue Spieler hinzugekommen sind
			for id, name := range currentPlayers {
				if _, exists := lastPlayers[id]; !exists {
					// Neuer Spieler gefunden
					p.log.Info("Spieler hat den Server betreten (Polling)", "player", name)
					message := fmt.Sprintf(p.joinMessage, name)
					p.broadcastMessage(message)
				}
			}
			
			// Prüfen, ob Spieler den Server verlassen haben
			for id, name := range lastPlayers {
				if _, exists := currentPlayers[id]; !exists {
					// Spieler hat den Server verlassen
					p.log.Info("Spieler hat den Server verlassen (Polling)", "player", name)
					message := fmt.Sprintf(p.quitMessage, name)
					p.broadcastMessage(message)
				}
			}
			
			// Spielerliste aktualisieren
			lastPlayers = currentPlayers
		}
	}
}

// Hilfsfunktion zum Senden einer Nachricht an alle Spieler
func (p *joinNotifierPlugin) broadcastMessage(message string) {
	comp := textComponent(message)
	
	for _, player := range p.proxy.Players() {
		if err := player.SendMessage(comp); err != nil {
			p.log.Error(err, "Fehler beim Senden der Nachricht", "player", player.Username())
		}
	}
}
