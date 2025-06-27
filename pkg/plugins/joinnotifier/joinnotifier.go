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
			log:           log,
			proxy:         p,
			playerCache:   make(map[uuid.UUID]playerInfo),
			// HIER EINSTELLUNGEN ANPASSEN:
			enabled:       true,
			joinMessage:   "&8[&aGatelite&8] &eDer Spieler &b%s &8(&7%s&8) &ehat den Server betreten!",
			quitMessage:   "&8[&aGatelite&8] &eDer Spieler &b%s &8(&7%s&8) &ehat den Server verlassen!",
			checkInterval: 3 * time.Second,
		}

		if !plugin.enabled {
			log.Info("Join Notifier Plugin ist deaktiviert.")
			return nil
		}

		// Registriere spezifische Event-Handler
		event.Subscribe(p.Event(), 0, plugin.handlePostLogin)
		event.Subscribe(p.Event(), 0, plugin.handleDisconnect)
		
		// Starte einen Hintergrundprozess zur Erkennung von Spieleränderungen (Fallback)
		go plugin.checkPlayersRegularly(ctx)

		log.Info("Join Notifier Plugin erfolgreich initialisiert!")
		
		return nil
	},
}

type playerInfo struct {
	name     string
	uuid     uuid.UUID
	joinTime time.Time
}

type joinNotifierPlugin struct {
	log           logr.Logger
	proxy         *proxy.Proxy
	enabled       bool
	joinMessage   string // Format: playerName, playerUUID
	quitMessage   string // Format: playerName, playerUUID
	checkInterval time.Duration
	
	mu           sync.RWMutex
	playerCache  map[uuid.UUID]playerInfo
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

// Handler für PostLoginEvent
func (p *joinNotifierPlugin) handlePostLogin(e *proxy.PostLoginEvent) {
	player := e.Player()
	if player == nil {
		return
	}

	playerName := player.Username()
	playerID := player.ID()
	playerUUID := playerID.String()
	
	p.mu.Lock()
	_, exists := p.playerCache[playerID]
	p.playerCache[playerID] = playerInfo{
		name:     playerName,
		uuid:     playerID,
		joinTime: time.Now(),
	}
	p.mu.Unlock()
	
	if !exists {
		p.log.Info("Spieler hat den Server betreten", 
			"player", playerName, 
			"uuid", playerUUID,
			"method", "PostLoginEvent")
		
		// Kurze UUID (erste 8 Zeichen)
		shortUUID := playerUUID
		if len(playerUUID) > 8 {
			shortUUID = playerUUID[:8] + "..."
		}
		
		message := fmt.Sprintf(p.joinMessage, playerName, shortUUID)
		p.broadcastMessage(message)
	}
}

// Handler für DisconnectEvent
func (p *joinNotifierPlugin) handleDisconnect(e *proxy.DisconnectEvent) {
	player := e.Player()
	if player == nil {
		return
	}

	playerName := player.Username()
	playerID := player.ID()
	playerUUID := playerID.String()
	
	p.mu.Lock()
	info, exists := p.playerCache[playerID]
	delete(p.playerCache, playerID)
	p.mu.Unlock()
	
	if exists {
		p.log.Info("Spieler hat den Server verlassen", 
			"player", playerName, 
			"uuid", playerUUID,
			"method", "DisconnectEvent",
			"sessionDuration", time.Since(info.joinTime).Round(time.Second))
		
		// Kurze UUID (erste 8 Zeichen)
		shortUUID := playerUUID
		if len(playerUUID) > 8 {
			shortUUID = playerUUID[:8] + "..."
		}
		
		message := fmt.Sprintf(p.quitMessage, playerName, shortUUID)
		p.broadcastMessage(message)
	}
}

// Regelmäßiger Check zur Erkennung von Spieleränderungen (Fallback-System)
func (p *joinNotifierPlugin) checkPlayersRegularly(ctx context.Context) {
	ticker := time.NewTicker(p.checkInterval)
	defer ticker.Stop()

	p.log.Info("Fallback-Spielerüberwachung gestartet", "interval", p.checkInterval)
	
	for {
		select {
		case <-ctx.Done():
			p.log.Info("Fallback-Spielerüberwachung beendet")
			return
		case <-ticker.C:
			p.checkPlayerChanges()
		}
	}
}

// Prüft auf Spieleränderungen (für den Fall, dass Events nicht funktionieren)
func (p *joinNotifierPlugin) checkPlayerChanges() {
	currentPlayers := make(map[uuid.UUID]playerInfo)
	
	// Aktuelle Spielerliste erfassen
	for _, player := range p.proxy.Players() {
		currentPlayers[player.ID()] = playerInfo{
			name:     player.Username(),
			uuid:     player.ID(),
			joinTime: time.Now(),
		}
	}
	
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// Prüfen, ob neue Spieler hinzugekommen sind
	for id, info := range currentPlayers {
		if _, exists := p.playerCache[id]; !exists {
			// Neuer Spieler gefunden (Fallback)
			p.log.Info("Spieler hat den Server betreten", 
				"player", info.name, 
				"uuid", info.uuid.String(),
				"method", "Fallback-Polling")
			
			playerUUID := info.uuid.String()
			shortUUID := playerUUID
			if len(playerUUID) > 8 {
				shortUUID = playerUUID[:8] + "..."
			}
			
			message := fmt.Sprintf(p.joinMessage, info.name, shortUUID)
			p.broadcastMessageUnsafe(message) // Wir haben bereits den Lock
			
			p.playerCache[id] = info
		}
	}
	
	// Prüfen, ob Spieler den Server verlassen haben
	for id, info := range p.playerCache {
		if _, exists := currentPlayers[id]; !exists {
			// Spieler hat den Server verlassen (Fallback)
			p.log.Info("Spieler hat den Server verlassen", 
				"player", info.name, 
				"uuid", info.uuid.String(),
				"method", "Fallback-Polling",
				"sessionDuration", time.Since(info.joinTime).Round(time.Second))
			
			playerUUID := info.uuid.String()
			shortUUID := playerUUID
			if len(playerUUID) > 8 {
				shortUUID = playerUUID[:8] + "..."
			}
			
			message := fmt.Sprintf(p.quitMessage, info.name, shortUUID)
			p.broadcastMessageUnsafe(message) // Wir haben bereits den Lock
			
			delete(p.playerCache, id)
		}
	}
}

// Hilfsfunktion zum Senden einer Nachricht an alle Spieler (mit Lock)
func (p *joinNotifierPlugin) broadcastMessage(message string) {
	comp := textComponent(message)
	
	for _, player := range p.proxy.Players() {
		if err := player.SendMessage(comp); err != nil {
			p.log.Error(err, "Fehler beim Senden der Nachricht", 
				"player", player.Username())
		}
	}
}

// Hilfsfunktion zum Senden einer Nachricht an alle Spieler (ohne Lock - bereits gelockt)
func (p *joinNotifierPlugin) broadcastMessageUnsafe(message string) {
	comp := textComponent(message)
	
	for _, player := range p.proxy.Players() {
		if err := player.SendMessage(comp); err != nil {
			p.log.Error(err, "Fehler beim Senden der Nachricht", 
				"player", player.Username())
		}
	}
}
