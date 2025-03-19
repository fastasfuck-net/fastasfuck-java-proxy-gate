package configdownloader

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/go-logr/logr"
	"go.minekube.com/gate/pkg/edition/java/proxy"
)

// Plugin ist ein Gate-Plugin, das in regelmäßigen Abständen eine Konfigurationsdatei
// herunterlädt und lokal speichert.
var Plugin = proxy.Plugin{
	Name: "ConfigDownloader",
	Init: func(ctx context.Context, p *proxy.Proxy) error {
		log := logr.FromContextOrDiscard(ctx)
		log.Info("Config Downloader Plugin wird initialisiert...")

		// Erstelle eine neue Instanz des Plugins
		plugin := &configDownloaderPlugin{
			log:           log,
			// HIER EINSTELLUNGEN ANPASSEN:
			configURL:     "https://fastasfuck.net/config",  // URL zur Konfigurationsdatei
			localPath:     "./config.yml",                           // Lokaler Pfad zum Speichern
			checkInterval: 1 * time.Minute,                          // Überprüfungsintervall
			enabled:       true,                                      // Plugin aktivieren/deaktivieren
		}

		if !plugin.enabled {
			log.Info("Config Downloader Plugin ist deaktiviert.")
			return nil
		}

		// Starte den Download-Prozess im Hintergrund
		go plugin.startConfigDownloader(ctx)

		log.Info("Config Downloader Plugin erfolgreich initialisiert!", 
			"configURL", plugin.configURL,
			"localPath", plugin.localPath,
			"checkInterval", plugin.checkInterval)
		return nil
	},
}

type configDownloaderPlugin struct {
	log           logr.Logger
	configURL     string
	localPath     string
	checkInterval time.Duration
	enabled       bool
}

// startConfigDownloader startet einen Goroutine, der die Konfigurationsdatei regelmäßig herunterlädt
func (p *configDownloaderPlugin) startConfigDownloader(ctx context.Context) {
	// Sofort beim Start herunterladen
	if err := p.downloadConfig(); err != nil {
		p.log.Error(err, "Initialer Konfigurationsdownload fehlgeschlagen")
	}

	// Dann regelmäßig herunterladen
	ticker := time.NewTicker(p.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := p.downloadConfig(); err != nil {
				p.log.Error(err, "Konfigurationsdownload fehlgeschlagen")
			}
		case <-ctx.Done():
			p.log.Info("Config Downloader beendet")
			return
		}
	}
}

// downloadConfig lädt die Konfigurationsdatei von der konfigurierten URL herunter
func (p *configDownloaderPlugin) downloadConfig() error {
	p.log.Info("Lade Konfigurationsdatei herunter...", "url", p.configURL)

	// HTTP-Anfrage an die Konfigurations-URL mit Kontext und Timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", p.configURL, nil)
	if err != nil {
		return fmt.Errorf("fehler beim Erstellen der HTTP-Anfrage: %w", err)
	}

	// User-Agent setzen
	req.Header.Set("User-Agent", "ConfigDownloader-Plugin/1.0")

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fehler beim Abrufen der Konfiguration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unerwarteter Status-Code beim Abrufen der Konfiguration: %d", resp.StatusCode)
	}

	// Datei zum Schreiben öffnen/erstellen
	tempFile := p.localPath + ".tmp"
	file, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("fehler beim Erstellen der temporären Datei: %w", err)
	}

	// Inhalt in temporäre Datei schreiben
	n, err := io.Copy(file, resp.Body)
	if err != nil {
		file.Close() // Schließe die Datei, auch wenn ein Fehler auftritt
		os.Remove(tempFile) // Lösche die temporäre Datei
		return fmt.Errorf("fehler beim Schreiben der Konfigurationsdatei: %w", err)
	}
	
	file.Close() // Datei schließen, bevor wir sie umbenennen

	// Überprüfe, ob die Datei leer ist
	if n == 0 {
		os.Remove(tempFile)
		return fmt.Errorf("heruntergeladene Konfigurationsdatei ist leer")
	}

	// Temporäre Datei zur Zieldatei umbenennen (atomare Operation)
	if err := os.Rename(tempFile, p.localPath); err != nil {
		return fmt.Errorf("fehler beim Umbenennen der temporären Datei: %w", err)
	}

	p.log.Info("Konfigurationsdatei erfolgreich heruntergeladen und gespeichert", 
		"größe", n, 
		"pfad", p.localPath)

	return nil
}
