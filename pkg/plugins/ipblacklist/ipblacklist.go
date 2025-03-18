// Package ipblacklist implementiert eine IP-Blacklist für Gate
package ipblacklist

import (
	"context"
	"encoding/json"
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
		// Korrigiert: Übergebe den korrekten Event-Typ
		event.Subscribe(p.Event(), proxy.LoginEvent{}, plugin.handleInbound)

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
	
	// Verbesserte IP-Extraktion mit Unterstützung für IPv6
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		p.log.Error(err, "Fehler beim Extrahieren der IP-Adresse", "addr", addr)
		return
	}
	ip := host

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

		// Die Disconnect-Methode wird aufgerufen, um die Verbindung zu trennen
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

	// HTTP-Anfrage an die Blacklist-URL mit Kontext und Timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", p.blacklistURL, nil)
	if err != nil {
		p.log.Error(err, "Fehler beim Erstellen der HTTP-Anfrage")
		return
	}

	// User-Agent setzen, um höflich zu sein
	req.Header.Set("User-Agent", "IPBlacklist-Plugin/1.0")

	client := &http.Client{}
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

	// Lese den Response-Body mit Größenbeschränkung
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // Max 10MB
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
	validCount := 0
	invalidCount := 0

	for _, entry := range entries {
		// Validiere die IP-Adresse
		if net.ParseIP(entry.IP) != nil {
			newBlacklist[entry.IP] = true
			validCount++
		} else {
			invalidCount++
			p.log.Info("Ungültige IP-Adresse in der Blacklist ignoriert", "ip", entry.IP)
		}
	}

	// Aktualisiere die Blacklist mit der neuen Liste
	p.blacklistMutex.Lock()
	p.blacklist = newBlacklist
	p.blacklistMutex.Unlock()

	p.log.Info("IP-Blacklist erfolgreich aktualisiert", 
		"validCount", validCount, 
		"invalidCount", invalidCount,
		"totalCount", len(newBlacklist))
}
