package gate

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"time"
	"io"
	"net/http"
	"context"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v2"
	"go.minekube.com/gate/pkg/gate"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	configURL      = "https://manager.fastasfuck.net/config/raw"
	reloadInterval = 5 * time.Minute
)

// Execute runs App() and calls os.Exit when finished.
func Execute() {
	if err := App().Run(os.Args); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func App() *cli.App {
	app := cli.NewApp()
	app.Name = "gate"
	app.Usage = "Gate is an extensible Minecraft proxy."
	app.Description = `A high performant & paralleled Minecraft proxy server with
	scalability, flexibility & excelled server version support.

Visit the website https://gate.minekube.com/ for more information.`

	var (
		debug      bool
		configFile string
		verbosity  int
		useRemoteConfig bool
	)
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:        "config",
			Aliases:     []string{"c"},
			Usage:       `config file (default: ./config.yml) Supports: yaml, json, env`,
			EnvVars:     []string{"GATE_CONFIG"},
			Destination: &configFile,
		},
		&cli.BoolFlag{
			Name:        "debug",
			Aliases:     []string{"d"},
			Usage:       "Enable debug mode and highest log verbosity",
			Destination: &debug,
			EnvVars:     []string{"GATE_DEBUG"},
		},
		&cli.IntFlag{
			Name:        "verbosity",
			Aliases:     []string{"v"},
			Usage:       "The higher the verbosity the more logs are shown",
			EnvVars:     []string{"GATE_VERBOSITY"},
			Destination: &verbosity,
		},
		&cli.BoolFlag{
			Name:        "remote-config",
			Usage:       "Load configuration from remote URL",
			Destination: &useRemoteConfig,
			EnvVars:     []string{"GATE_REMOTE_CONFIG"},
		},
	}
	app.Action = func(c *cli.Context) error {
		var v *viper.Viper
		var err error
		
		if useRemoteConfig {
			// Load remote config first
			v, err = loadRemoteConfig(c.Context)
			if err != nil {
				// Log the error but continue with local config
				fmt.Fprintf(os.Stderr, "Error loading remote config: %v. Falling back to local config.\n", err)
				v, err = initViper(c, configFile)
				if err != nil {
					return cli.Exit(err, 1)
				}
			}
		} else {
			// Init viper with local config
			v, err = initViper(c, configFile)
			if err != nil {
				return cli.Exit(err, 1)
			}
		}
		
		// Load config
		cfg, err := gate.LoadConfig(v)
		if err != nil {
			// A config file is only required to exist when explicit config flag was specified.
			// Otherwise, we just use the default config.
			if !(errors.As(err, &viper.ConfigFileNotFoundError{}) || os.IsNotExist(err)) || c.IsSet("config") {
				err = fmt.Errorf("error reading config file %q: %w", v.ConfigFileUsed(), err)
				return cli.Exit(err, 2)
			}
		}

		// Flags overwrite config
		debug = debug || cfg.Editions.Java.Config.Debug
		cfg.Editions.Java.Config.Debug = debug

		if !c.IsSet("verbosity") && debug {
			verbosity = math.MaxInt8
		}

		// Create logger
		log, err := newLogger(debug, verbosity)
		if err != nil {
			return cli.Exit(fmt.Errorf("error creating zap logger: %w", err), 1)
		}
		c.Context = logr.NewContext(c.Context, log)

		log.Info("logging verbosity", "verbosity", verbosity)
		log.Info("using config file", "config", v.ConfigFileUsed())
		
		// If remote config is used, start the background reloader
		if useRemoteConfig {
			go startRemoteConfigReloader(c.Context, log, cfg)
		}

		// Start Gate
		if err = gate.Start(c.Context,
			gate.WithConfig(*cfg),
			gate.WithAutoConfigReload(v.ConfigFileUsed()),
		); err != nil {
			return cli.Exit(fmt.Errorf("error running Gate: %w", err), 1)
		}
		return nil
	}
	return app
}

// loadRemoteConfig loads the configuration from the remote URL
func loadRemoteConfig(ctx context.Context) (*viper.Viper, error) {
	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, configURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	
	// Send the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()
	
	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-OK status code: %d", resp.StatusCode)
	}
	
	// Read response body
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	
	// Write to a temporary file
	tempFile := "config_remote.yml"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to write temporary config file: %w", err)
	}
	
	// Load the config into viper
	v := viper.New()
	v.SetConfigFile(tempFile)
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	
	return v, nil
}

// startRemoteConfigReloader periodically reloads the configuration from the remote URL
func startRemoteConfigReloader(ctx context.Context, log logr.Logger, initialCfg *gate.Config) {
	ticker := time.NewTicker(reloadInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			log.Info("Reloading configuration from remote URL", "url", configURL)
			
			// Load the new config
			v, err := loadRemoteConfig(ctx)
			if err != nil {
				log.Error(err, "Failed to reload remote configuration")
				continue
			}
			
			// Parse the config
			cfg, err := gate.LoadConfig(v)
			if err != nil {
				log.Error(err, "Failed to parse remote configuration")
				continue
			}
			
			// Apply the new config
			// Note: Gate might need a restart or a specific API to reload config at runtime
			// This implementation assumes there's a way to signal Gate to reload its config
			log.Info("Successfully loaded new configuration from remote URL")
			
			// Here you would typically call an API to apply the new config to the running Gate instance
			// For example: gate.ReloadConfig(cfg)
			
		case <-ctx.Done():
			log.Info("Stopping remote configuration reloader")
			return
		}
	}
}

func initViper(c *cli.Context, configFile string) (*viper.Viper, error) {
	v := gate.Viper
	if c.IsSet("config") {
		v.SetConfigFile(configFile)
	} else {
		v.SetConfigName("config")
		v.AddConfigPath(".")
	}
	// Load Environment Variables
	v.SetEnvPrefix("GATE")
	v.AutomaticEnv() // read in environment variables that match
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	return v, nil
}

// newLogger returns a new zap logger with a modified production
// or development default config to ensure human readability.
func newLogger(debug bool, v int) (l logr.Logger, err error) {
	var cfg zap.Config
	if debug {
		cfg = zap.NewDevelopmentConfig()
	} else {
		cfg = zap.NewProductionConfig()
	}
	cfg.Level = zap.NewAtomicLevelAt(zapcore.Level(-v))

	cfg.Encoding = "console"
	cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	zl, err := cfg.Build()
	if err != nil {
		return logr.Discard(), err
	}
	return zapr.NewLogger(zl), nil
}
