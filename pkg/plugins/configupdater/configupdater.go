package configupdater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"go.minekube.com/gate/pkg/edition/java/proxy"
)

// Plugin ist ein ConfigUpdater-Plugin, das regelmäßig Konfigurationen von 
// einem entfernten Server herunterlädt und aktualisiert
var Plugin = proxy.Plugin{
	Name: "ConfigUpdater",
	Init: func(ctx context.Context, p *proxy.Proxy) error {
		log := logr.FromContextOrDiscard(ctx)
		log.Info("ConfigUpdater Plugin wird initialisiert...")

		// Erstelle eine neue Instanz des Plugins
		plugin := &configUpdaterPlugin{
			log:           log,
			mu:            sync.RWMutex{},
			// HIER EINSTELLUNGEN ANPASSEN:
			configURL:     "https://example.com/config.json", // URL zur Konfiguration
			updateInterval: time.Minute,                      // 1 Minute Update-Intervall
			configPath:    "./downloaded_config.json",        // Lokaler Pfad für die Konfiguration
			enabled:       true,                              // Plugin aktivieren/deaktivieren
			httpTimeout:   30 * time.Second,                  // Timeout für HTTP-Anfragen
		}

		if !plugin.enabled {
			log.Info("ConfigUpdater Plugin ist deaktiviert.")
			return nil
		}

		// Erstelle Verzeichnis für die Konfiguration falls es nicht existiert
		if err := os.MkdirAll(filepath.Dir(plugin.configPath), 0755); err != nil {
			log.Error(err, "Fehler beim Erstellen des Konfigurationsverzeichnisses")
			// Fortfahren, da dies nicht kritisch ist
		}

		// Starte den Update-Prozess im Hintergrund
		go plugin.startConfigUpdater(ctx)

		log.Info("ConfigUpdater Plugin erfolgreich initialisiert!",
			"configURL", plugin.configURL,
			"updateInterval", plugin.updateInterval,
			"configPath", plugin.configPath)
		return nil
	},
}

type configUpdaterPlugin struct {
	log            logr.Logger
	mu             sync.RWMutex
	configURL      string
	updateInterval time.Duration
	configPath     string
	enabled        bool
	httpTimeout    time.Duration
	lastConfig     map[string]interface{} // Speichert die zuletzt heruntergeladene Konfiguration
}

// ConfigProcessor ist eine Funktion, die aufgerufen wird, wenn eine neue Konfiguration verfügbar ist
type ConfigProcessor func(config map[string]interface{}) error

var configProcessors []ConfigProcessor

// RegisterConfigProcessor registriert eine Funktion, die aufgerufen wird, 
// wenn eine neue Konfiguration verfügbar ist
func RegisterConfigProcessor(processor ConfigProcessor) {
	configProcessors = append(configProcessors, processor)
}

// startConfigUpdater startet einen Goroutine, der die Konfiguration regelmäßig aktualisiert
func (p *configUpdaterPlugin) startConfigUpdater(ctx context.Context) {
	// Sofort beim Start aktualisieren
	if err := p.updateConfig(); err != nil {
		p.log.Error(err, "Initialer Konfigurations-Update fehlgeschlagen")
	}

	// Dann regelmäßig aktualisieren
	ticker := time.NewTicker(p.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := p.updateConfig(); err != nil {
				p.log.Error(err, "Konfigurations-Update fehlgeschlagen")
			}
		case <-ctx.Done():
			p.log.Info("Config Updater beendet")
			return
		}
	}
}

// updateConfig lädt die aktuelle Konfiguration von der konfigurierten URL
func (p *configUpdaterPlugin) updateConfig() error {
	p.log.Info("Aktualisiere Konfiguration...", "url", p.configURL)

	// HTTP-Anfrage an die Konfigurations-URL mit Kontext und Timeout
	ctx, cancel := context.WithTimeout(context.Background(), p.httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", p.configURL, nil)
	if err != nil {
		return fmt.Errorf("fehler beim Erstellen der HTTP-Anfrage: %w", err)
	}

	// User-Agent setzen, um höflich zu sein
	req.Header.Set("User-Agent", "ConfigUpdater-Plugin/1.0")

	client := &http.Client{
		Timeout: p.httpTimeout,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fehler beim Abrufen der Konfiguration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unerwarteter Status-Code beim Abrufen der Konfiguration: %d", resp.StatusCode)
	}

	// Lese den Response-Body mit Größenbeschränkung
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // Max 10MB
	if err != nil {
		return fmt.Errorf("fehler beim Lesen der Konfigurations-Antwort: %w", err)
	}

	// Versuche die Konfiguration zu parsen
	var config map[string]interface{}
	if err := json.Unmarshal(body, &config); err != nil {
		return fmt.Errorf("fehler beim Parsen der Konfiguration: %w", err)
	}

	// Prüfe, ob die Konfiguration sich geändert hat
	hasChanged := !p.configEquals(config)

	// Speichere die Konfiguration
	p.mu.Lock()
	p.lastConfig = config
	p.mu.Unlock()

	// Speichere die Konfiguration in einer Datei
	if err := p.saveConfig(body); err != nil {
		p.log.Error(err, "Fehler beim Speichern der Konfiguration")
		// Wir fahren trotzdem fort, da wir die Konfiguration im Speicher haben
	}

	// Benachrichtige Konfigurationsverarbeiter, wenn sich etwas geändert hat
	if hasChanged {
		p.log.Info("Konfiguration hat sich geändert, benachrichtige Verarbeiter")
		p.notifyConfigProcessors(config)
	} else {
		p.log.V(1).Info("Konfiguration hat sich nicht geändert")
	}

	p.log.Info("Konfiguration erfolgreich aktualisiert")
	return nil
}

// configEquals prüft, ob die neu heruntergeladene Konfiguration mit der vorherigen übereinstimmt
func (p *configUpdaterPlugin) configEquals(newConfig map[string]interface{}) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Wenn wir noch keine Konfiguration haben, hat sich die Konfiguration geändert
	if p.lastConfig == nil {
		return false
	}

	// Vergleiche die Konfigurationen
	oldJSON, err := json.Marshal(p.lastConfig)
	if err != nil {
		p.log.Error(err, "Fehler beim Serialisieren der alten Konfiguration")
		return false
	}

	newJSON, err := json.Marshal(newConfig)
	if err != nil {
		p.log.Error(err, "Fehler beim Serialisieren der neuen Konfiguration")
		return false
	}

	return string(oldJSON) == string(newJSON)
}

// saveConfig speichert die Konfiguration in einer Datei
func (p *configUpdaterPlugin) saveConfig(configData []byte) error {
	// Erstelle temporäre Datei
	tempFile := p.configPath + ".tmp"
	if err := os.WriteFile(tempFile, configData, 0644); err != nil {
		return fmt.Errorf("fehler beim Schreiben der temporären Konfigurationsdatei: %w", err)
	}

	// Benenne temporäre Datei um, um atomische Ersetzung zu gewährleisten
	if err := os.Rename(tempFile, p.configPath); err != nil {
		return fmt.Errorf("fehler beim Umbenennen der temporären Konfigurationsdatei: %w", err)
	}

	return nil
}

// notifyConfigProcessors benachrichtigt alle registrierten Konfigurationsverarbeiter
func (p *configUpdaterPlugin) notifyConfigProcessors(config map[string]interface{}) {
	for _, processor := range configProcessors {
		if err := processor(config); err != nil {
			p.log.Error(err, "Fehler beim Verarbeiten der Konfiguration")
		}
	}
}

// GetConfig gibt die aktuelle Konfiguration zurück
func (p *configUpdaterPlugin) GetConfig() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	// Erstelle eine Kopie der Konfiguration, um Race-Conditions zu vermeiden
	if p.lastConfig == nil {
		return nil
	}
	
	configCopy := make(map[string]interface{}, len(p.lastConfig))
	for k, v := range p.lastConfig {
		configCopy[k] = v
	}
	
	return configCopy
}
