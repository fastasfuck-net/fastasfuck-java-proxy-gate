package remoteconfig

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/viper"
	"go.minekube.com/gate/pkg/edition/java/proxy"
	"go.minekube.com/gate/pkg/gate"
)

const (
	configURL      = "https://manager.fastasfuck.net/config/raw"
	reloadInterval = 5 * time.Minute
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
	if err := loadRemoteConfig(ctx, proxy); err != nil {
		logger.Error(err, "Failed to load initial remote configuration")
		// Continue anyway, using local config
	}

	// Start background periodic reload
	go periodicConfigReload(ctx, proxy)

	return nil
}

func periodicConfigReload(ctx context.Context, proxy *proxy.Proxy) {
	logger := logr.FromContextOrDiscard(ctx)
	ticker := time.NewTicker(reloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Reload config from remote URL
			if err := loadRemoteConfig(ctx, proxy); err != nil {
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

func loadRemoteConfig(ctx context.Context, proxy *proxy.Proxy) error {
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

	// Write to a temporary file
	tempFile := "config_remote.yml"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temporary config file: %w", err)
	}

	// Load the config into viper
	v := viper.New()
	v.SetConfigFile(tempFile)
	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Load the new config
	cfg, err := gate.LoadConfig(v)
	if err != nil {
		return fmt.Errorf("failed to load config from viper: %w", err)
	}

	// Apply the new config to the proxy
	// Note: This depends on Gate's internal mechanisms and may need adjustment
	if err := proxy.ApplyConfig(*cfg); err != nil {
		return fmt.Errorf("failed to apply new configuration: %w", err)
	}

	logger.Info("Successfully applied remote configuration")
	return nil
}
