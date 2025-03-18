package remoteconfig

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/viper"
	"go.minekube.com/gate/pkg/edition/java/proxy"
)

const (
	configURL      = "https://manager.fastasfuck.net/config/raw"
	reloadInterval = 5 * time.Minute
	configFilePath = "config_remote.yml" // Path where the remote config will be saved
)

// Plugin is the remote config loader plugin.
var Plugin = proxy.Plugin{
	Name: "RemoteConfigLoader",
	Init: Init,
}

// Init initializes the remote config loader plugin.
func Init(ctx context.Context, proxy *proxy.Proxy) error {
	logger := logr.FromContextOrDiscard(ctx)
	logger.Info("Initializing remote configuration loader plugin")

	// Get initial configuration
	if err := loadRemoteConfig(ctx); err != nil {
		logger.Error(err, "Failed to load initial remote configuration")
		// Continue anyway, using local config
	}

	// Start background periodic reload
	go periodicConfigReload(ctx)

	return nil
}

func periodicConfigReload(ctx context.Context) {
	logger := logr.FromContextOrDiscard(ctx)
	ticker := time.NewTicker(reloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Reload config from remote URL
			if err := loadRemoteConfig(ctx); err != nil {
				logger.Error(err, "Failed to reload remote configuration")
				continue
			}
			logger.Info("Successfully reloaded configuration from remote URL")
		case <-ctx.Done():
			logger.Info("Stopping remote configuration loader")
			return
		}
	}
}

func loadRemoteConfig(ctx context.Context) error {
	logger := logr.FromContextOrDiscard(ctx)
	logger.Info("Loading configuration from remote URL", "url", configURL)

	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, configURL, nil)
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

	// Validate the config by attempting to load it in viper
	v := viper.New()
	v.SetConfigType("yaml") // Specify that it's YAML format
	if err := v.ReadConfig(strings.NewReader(string(data))); err != nil {
		return fmt.Errorf("invalid configuration format: %w", err)
	}

	// Write to the config file
	if err := os.WriteFile(configFilePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	logger.Info("Successfully saved remote configuration to file", "path", configFilePath)
	return nil
}
