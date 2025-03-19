package joinnotifier

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/robinbraemer/event"
	"go.minekube.com/gate/pkg/edition/java/proxy"
)

// Plugin ist ein Gate-Plugin, das bei jedem Spieler-Join eine Nachricht im Chat anzeigt
var Plugin = proxy.Plugin{
	Name: "JoinNotifier",
	Init: func(ctx context.Context, p *proxy.Proxy) error {
		log := logr.FromContextOrDiscard(ctx)
		log.Info("Join Notifier Plugin wird initialisiert...")

		// Erstelle eine neue Instanz des Plugins
		plugin := &joinNotifierPlugin{
			log:          log,
			proxy:        p,
			// HIER EINSTELLUNGEN ANPASSEN:
			enabled:      true,                                 // Plugin aktivieren/deaktivieren
			joinMessage:  "&8[&aGatelite&8] &eDer Spieler &b%s &ehat den Server betreten!",
			quitMessage:  "&8[&aGatelite&8] &eDer Spieler &b%s &ehat den Server verlassen!",
		}

		if !plugin.enabled {
			log.Info("Join Notifier Plugin ist deaktiviert.")
			return nil
		}

		// Event-Handler registrieren
		subscription := event.Subscribe(p.Event(), 0, plugin.handlePlayerJoin)
		disconnectSubscription := event.Subscribe(p.Event(), 0, plugin.handlePlayerDisconnect)

		log.Info("Join Notifier Plugin erfolgreich initialisiert!")
		
		return nil
	},
}

type joinNotifierPlugin struct {
	log          logr.Logger
	proxy        *proxy.Proxy
	enabled      bool
	joinMessage  string
	quitMessage  string
}

// Wandelt Minecraft-Farbcodes (z.B. &a) in ihre entsprechenden Codes um
func colorize(message string) string {
	return strings.ReplaceAll(message, "&", "§")
}

// PlayerJoinEvent-Handler
func (p *joinNotifierPlugin) handlePlayerJoin(e *proxy.PostLoginEvent) {
	player := e.Player()
	if player == nil {
		return
	}

	// Hole den Spielernamen
	playerName := player.Username()
	
	// Erstelle die formatierte Nachricht
	message := fmt.Sprintf(p.joinMessage, playerName)
	coloredMessage := colorize(message)
	
	p.log.Info("Spieler hat den Server betreten", "player", playerName)
	
	// Sende Nachricht an alle Spieler
	go func() {
		// Warte kurz, damit der Login abgeschlossen ist
		time.Sleep(500 * time.Millisecond)
		p.broadcastMessage(coloredMessage)
	}()
}

// PlayerDisconnectEvent-Handler
func (p *joinNotifierPlugin) handlePlayerDisconnect(e *proxy.DisconnectEvent) {
	player := e.Player()
	if player == nil {
		return
	}

	// Hole den Spielernamen
	playerName := player.Username()
	
	// Erstelle die formatierte Nachricht
	message := fmt.Sprintf(p.quitMessage, playerName)
	coloredMessage := colorize(message)
	
	p.log.Info("Spieler hat den Server verlassen", "player", playerName)
	
	// Sende Nachricht an alle Spieler
	p.broadcastMessage(coloredMessage)
}

// Hilfsfunktion zum Senden einer Nachricht an alle Spieler
func (p *joinNotifierPlugin) broadcastMessage(message string) {
	for _, player := range p.proxy.Players() {
		// Sende die Nachricht an den Spieler
		player.SendMessage(message)
	}
}
