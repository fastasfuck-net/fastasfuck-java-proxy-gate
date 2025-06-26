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
// herunterlädt und das Auto-Reload von Gate triggert.
var Plugin = proxy.Plugin{
	Name: "ConfigDownloader",
	Init: func(ctx context.Context, p *proxy.Proxy) error {
		log := logr.FromContextOrDiscard(ctx)
		log.Info("Config Downloader Plugin wird initialisiert...")

		// Erstelle eine neue Instanz des Plugins
		plugin := &configDownloaderPlugin{
			log:           log,
			// HIER EINSTELLUNGEN ANPASSEN:
			configURL:     "https://manager.fastasfuck.net/config",  // URL zur Konfigurationsdatei
			localPath:     "./config.yml",                           // Lokaler Pfad zum Speichern
			checkInterval: 1 * time.Minute,                          // Überprüfungsintervall
			enabled:       true,                                      // Plugin aktivieren/deaktivieren
			forceReload:   true,                                      // File-Touch nach Download
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
	forceReload   bool
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

	// Prüfe zuerst ob sich der Inhalt geändert hat
	newContent, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("fehler beim Lesen der Response: %w", err)
	}

	// Prüfe ob die neue Config anders ist als die aktuelle
	if !p.hasConfigChanged(newContent) {
		p.log.Info("Config hat sich nicht geändert, kein Download nötig")
		return nil
	}

	// Backup der aktuellen Config erstellen
	if err := p.backupCurrentConfig(); err != nil {
		p.log.Error(err, "Warnung: Konnte keine Backup-Datei erstellen")
	}

	// Neue Config speichern
	if err := p.saveConfig(newContent); err != nil {
		return err
	}

	// Auto-Reload triggern wenn aktiviert
	if p.forceReload {
		if err := p.triggerAutoReload(); err != nil {
			p.log.Error(err, "Warnung: Konnte Auto-Reload nicht triggern")
		}
	}

	p.log.Info("Konfigurationsdatei erfolgreich heruntergeladen und gespeichert", 
		"größe", len(newContent), 
		"pfad", p.localPath)

	return nil
}

// hasConfigChanged prüft ob sich der Config-Inhalt geändert hat
func (p *configDownloaderPlugin) hasConfigChanged(newContent []byte) bool {
	// Aktuelle Config-Datei lesen
	currentContent, err := os.ReadFile(p.localPath)
	if err != nil {
		// Datei existiert nicht oder kann nicht gelesen werden -> auf jeden Fall herunterladen
		return true
	}

	// Inhalte vergleichen
	return string(currentContent) != string(newContent)
}

// backupCurrentConfig erstellt ein Backup der aktuellen Config
func (p *configDownloaderPlugin) backupCurrentConfig() error {
	backupPath := p.localPath + ".backup." + time.Now().Format("20060102-150405")
	
	// Aktuelle Config lesen
	content, err := os.ReadFile(p.localPath)
	if err != nil {
		return err // Datei existiert möglicherweise nicht
	}

	// Backup schreiben
	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		return fmt.Errorf("fehler beim Erstellen des Backups: %w", err)
	}

	p.log.Info("Backup der aktuellen Config erstellt", "backup", backupPath)
	return nil
}

// saveConfig speichert die neue Config atomisch
func (p *configDownloaderPlugin) saveConfig(content []byte) error {
	// Temporäre Datei erstellen
	tempFile := p.localPath + ".tmp"
	
	if err := os.WriteFile(tempFile, content, 0644); err != nil {
		return fmt.Errorf("fehler beim Schreiben der temporären Datei: %w", err)
	}

	// Atomisch umbenennen
	if err := os.Rename(tempFile, p.localPath); err != nil {
		os.Remove(tempFile) // Aufräumen bei Fehler
		return fmt.Errorf("fehler beim Umbenennen der temporären Datei: %w", err)
	}

	return nil
}

// triggerAutoReload triggert Gate's Auto-Reload durch File-Modification
func (p *configDownloaderPlugin) triggerAutoReload() error {
	p.log.Info("Triggere Auto-Reload durch File-Touch...")

	// Kleine Wartezeit um sicherzustellen, dass die Datei vollständig geschrieben wurde
	time.Sleep(100 * time.Millisecond)

	// File-Touch: Aktualisiere die Modifikationszeit der Datei
	now := time.Now()
	if err := os.Chtimes(p.localPath, now, now); err != nil {
		return fmt.Errorf("fehler beim File-Touch: %w", err)
	}

	p.log.Info("Auto-Reload wurde getriggert")
	return nil
}

// Optional: Methode zum manuellen Triggern eines Gate-Restarts
func (p *configDownloaderPlugin) forceRestart() {
	p.log.Info("WICHTIG: Config wurde geändert!")
	p.log.Info("Für sofortige Anwendung aller Änderungen wird ein Gate-Restart empfohlen.")
	p.log.Info("Verwenden Sie 'systemctl restart gate' oder Ihren Process-Manager.")
	
	// Optional: Gate automatisch beenden (wenn von systemd/supervisor verwaltet)
	// Vorsicht: Nur aktivieren wenn Sie sicher sind, dass Gate automatisch neu gestartet wird!
	// 
	// p.log.Info("Gate wird für automatischen Restart beendet...")
	// time.Sleep(1 * time.Second) // Kurz warten damit Log-Message ausgegeben wird
	// os.Exit(0)
}
