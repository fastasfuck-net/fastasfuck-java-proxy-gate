// Package remoteconfig provides a plugin to fetch configuration from a remote source
package remoteconfig

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-logr/logr"
	"go.minekube.com/gate/pkg/edition/java/proxy"
	"go.minekube.com/gate/pkg/util/configutil"
)

const (
	configURL      = "https://manager.fastasfuck.net/config/raw"
	reloadInterval = 5 * time.Minute
	configFileName = "config_remote.yml"
)

// Plugin is a Gate plugin that fetches configuration from a remote source
var Plugin = proxy.Plugin{
	Name: "RemoteConfig",
	Init: Init,
}

// Init initializes the remote configuration plugin
func Init(ctx context.Context, proxy *proxy.Proxy) error {
	// Extract logger from context or create a new one
	log, ok := logr.FromContext(ctx)
	if !ok {
		// If no logger in context, create a new one
		log = logr.Discard()
	}
	log = log.WithName("remoteconfig")
	
	// Create a temporary directory that will be writable
	tempDir, err := os.MkdirTemp("", "gate-config")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	
	// Use the temporary directory for the config file
	configPath := filepath.Join(tempDir, configFileName)
	
	log.Info("Remote configuration plugin initialized", "tempDir", tempDir, "configPath", configPath)
	
	// Load initial configuration
	if err := loadConfig(configPath, log); err != nil {
		return fmt.Errorf("failed to load initial remote configuration: %w", err)
	}
	
	// Start background reloader
	go configReloader(ctx, configPath, log)
	
	return nil
}

// loadConfig fetches and saves the remote configuration
func loadConfig(configPath string, log logr.Logger) error {
	// Create HTTP request
	req, err := http.NewRequest(http.MethodGet, configURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	
	// Send the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()
	
	// Check response status
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-OK status code: %d", resp.StatusCode)
	}
	
	// Read response body
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}
	
	// Write to the temporary file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	
	// Notify Gate about config change
	if err := configutil.ReloadConfig(configPath); err != nil {
		log.Error(err, "Failed to reload config from remote source")
		return err
	}
	
	log.Info("Successfully loaded configuration from remote URL", "url", configURL)
	return nil
}

// configReloader periodically reloads the configuration from the remote URL
func configReloader(ctx context.Context, configPath string, log logr.Logger) {
	ticker := time.NewTicker(reloadInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			log.V(1).Info("Reloading configuration from remote URL", "url", configURL)
			
			if err := loadConfig(configPath, log); err != nil {
				log.Error(err, "Failed to reload remote configuration")
			}
			
		case <-ctx.Done():
			log.Info("Stopping remote configuration reloader")
			return
		}
	}
}
