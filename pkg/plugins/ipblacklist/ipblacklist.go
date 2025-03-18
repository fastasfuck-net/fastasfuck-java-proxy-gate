// Package ipblacklist implementiert eine IP-Blacklist für Gate
package ipblacklist

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/robinbraemer/event"
	c "go.minekube.com/common/minecraft/component"
	"go.minekube.com/gate/pkg/edition/java/proxy"
)

// Plugin ist ein IP-Blacklist-Plugin, das Verbindungen von Spielern ablehnt,
// die auf einer Blacklist stehen, die regelmäßig von einer URL aktualisiert wird.
var Plugin = proxy.Plugin{
	Name: "IPBlacklist",
	Init: func(ctx context.Context, p *proxy.Proxy) error {
		log := logr.FromContextOrDiscard(ctx)
		log.Info("IP Blacklist Plugin wird initialisiert...")

		// Erstelle eine neue Instanz des Plugins
		plugin := &blacklistPlugin{
			log:            log,
			blacklist:      make(map[string]bool),
			blacklistURL:   "https://fastasfuck.net/blacklist.json", // URL zur Blacklist
			updateInterval: 5 * time.Minute,                         // Update-Intervall
		}

		// Starte den Update-Prozess im Hintergrund
		go plugin.startBlacklistUpdater(ctx)

		// Registriere den Event-Handler für eingehende Verbindungen
		event.Subscribe(p.Event(), 0, plugin.handleInbound)

		log.Info("IP Blacklist Plugin erfolgreich initialisiert!")
		return nil
	},
}

type blacklistPlugin struct {
	log            logr.Logger
	blacklist      map[string]bool
	blacklistMutex sync.RWMutex
	blacklistURL   string
	updateInterval time.Duration
}

// BlacklistEntry repräsentiert einen Eintrag in der Blacklist
type BlacklistEntry struct {
	IP string `json:"ip"`
}

// handleInbound wird aufgerufen, wenn ein Spieler versucht, sich zu verbinden
func (p *blacklistPlugin) handleInbound(e *proxy.LoginEvent) {
	// Extrahiere die IP-Adresse aus der Verbindung
	addr := e.Player().RemoteAddr().String()
	ip := strings.Split(addr, ":")[0] // Entferne den Port

	// Prüfe, ob die IP in der Blacklist ist
	p.blacklistMutex.RLock()
	blocked := p.blacklist[ip]
	p.blacklistMutex.RUnlock()

	if blocked {
		p.log.Info("Verbindung von geblockter IP abgelehnt", "ip", ip)

		// Ablehnen der Verbindung mit einer Nachricht
		disconnectMessage := &c.Text{
			Content: "You are on the global blacklist of fastasfuck.net\nTo appeal go to appeal.fastasfuck.net",
		}

		// Korrigiert: Die Disconnect-Methode gibt keinen Wert zurück
		e.Player().Disconnect(disconnectMessage)
	}
}

// startBlacklistUpdater startet einen Goroutine, der die Blacklist regelmäßig aktualisiert
func (p *blacklistPlugin) startBlacklistUpdater(ctx context.Context) {
	// Sofort beim Start aktualisieren
	p.updateBlacklist()

	// Dann regelmäßig aktualisieren
	ticker := time.NewTicker(p.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.updateBlacklist()
		case <-ctx.Done():
			p.log.Info("Blacklist Updater beendet")
			return
		}
	}
}

// updateBlacklist lädt die aktuelle Blacklist von der konfigurierten URL
func (p *blacklistPlugin) updateBlacklist() {
	p.log.Info("Aktualisiere IP-Blacklist...", "url", p.blacklistURL)

	// HTTP-Anfrage an die Blacklist-URL
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest("GET", p.blacklistURL, nil)
	if err != nil {
		p.log.Error(err, "Fehler beim Erstellen der HTTP-Anfrage")
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		p.log.Error(err, "Fehler beim Abrufen der Blacklist")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		p.log.Error(nil, "Unerwarteter Status-Code beim Abrufen der Blacklist", "statusCode", resp.StatusCode)
		return
	}

	// Lese den Response-Body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		p.log.Error(err, "Fehler beim Lesen der Blacklist-Antwort")
		return
	}

	// Parse die Blacklist-Einträge
	var entries []BlacklistEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		p.log.Error(err, "Fehler beim Parsen der Blacklist-Daten")
		return
	}

	// Aktualisiere die Blacklist
	newBlacklist := make(map[string]bool, len(entries))
	for _, entry := range entries {
		// Validiere die IP-Adresse
		if net.ParseIP(entry.IP) != nil {
			newBlacklist[entry.IP] = true
		} else {
			p.log.Info("Ungültige IP-Adresse in der Blacklist ignoriert", "ip", entry.IP)
		}
	}

	// Aktualisiere die Blacklist mit der neuen Liste
	p.blacklistMutex.Lock()
	p.blacklist = newBlacklist
	p.blacklistMutex.Unlock()

	p.log.Info("IP-Blacklist erfolgreich aktualisiert", "count", len(newBlacklist))
}
