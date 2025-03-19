package joinnotifier

import (
	"context"
	"github.com/go-logr/logr"
	"github.com/robinbraemer/event"
	"go.minekube.com/common/minecraft/component"
	"go.minekube.com/common/minecraft/component/codec/legacy"
	"go.minekube.com/gate/pkg/edition/java/proxy"
)

// Plugin ist ein Gate-Plugin, das versucht, Spieler-Join/Leave in Lite-Modus zu erkennen
var Plugin = proxy.Plugin{
	Name: "JoinNotifier",
	Init: func(ctx context.Context, p *proxy.Proxy) error {
		log := logr.FromContextOrDiscard(ctx)
		log.Info("Join Notifier Plugin wird initialisiert...")

		// Erstelle eine neue Instanz des Plugins
		plugin := &joinNotifierPlugin{
			log:        log,
			proxy:      p,
			// HIER EINSTELLUNGEN ANPASSEN:
			enabled:    true,
			joinMessage: "&8[&aGatelite&8] &eDer Spieler ist dem Server beigetreten!",
		}

		if !plugin.enabled {
			log.Info("Join Notifier Plugin ist deaktiviert.")
			return nil
		}

		// In Gate Lite können wir auf "niedrigere" Netzwerk-Events hören
		// Dies ist nur ein Versuch, da die verfügbaren Events begrenzt sind
		_ = event.Subscribe(p.Event(), 0, plugin.handleProxyInboundConnection)
		
		log.Info("Join Notifier Plugin erfolgreich initialisiert!")
		
		return nil
	},
}

type joinNotifierPlugin struct {
	log         logr.Logger
	proxy       *proxy.Proxy
	enabled     bool
	joinMessage string
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

// Versucht, auf eingehende Verbindungen zu reagieren
func (p *joinNotifierPlugin) handleProxyInboundConnection(e *proxy.ProxyInboundConnectionEvent) {
	// Dieser Event könnte im Gate Lite Modus ausgelöst werden
	// Aber wir haben keinen Zugriff auf den Spielernamen in diesem Stadium
	
	p.log.Info("Eingehende Verbindung erkannt", "remoteAddr", e.RemoteAddress())
	
	// Versuche, eine Nachricht an alle Spieler zu senden
	// Dies könnte nur funktionieren, wenn bereits Spieler verbunden sind
	p.broadcastMessage(p.joinMessage)
}

// Hilfsfunktion zum Senden einer Nachricht an alle Spieler
func (p *joinNotifierPlugin) broadcastMessage(message string) {
	comp := textComponent(message)
	
	// Gate.Players() könnte im Lite-Modus leer sein
	for _, player := range p.proxy.Players() {
		if err := player.SendMessage(comp); err != nil {
			p.log.Error(err, "Fehler beim Senden der Nachricht", "player", player.Username())
		}
	}
}
