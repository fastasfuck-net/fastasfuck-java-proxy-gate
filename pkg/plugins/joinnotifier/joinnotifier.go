package litejoinnotifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"go.minekube.com/gate/pkg/edition/java/lite/config"
	"go.minekube.com/gate/pkg/edition/java/proxy"
	"go.minekube.com/gate/pkg/edition/java/proxy/phase"
	"go.minekube.com/gate/pkg/edition/java/netmc"
	"go.minekube.com/gate/pkg/util/uuid"
)

// Plugin is a Gate plugin that monitors player connections in Lite mode
// and sends notifications to an API endpoint when players join.
var Plugin = proxy.Plugin{
	Name: "LiteJoinNotifier",
	Init: func(ctx context.Context, p *proxy.Proxy) error {
		log := logr.FromContextOrDiscard(ctx)
		log.Info("Lite Join Notifier Plugin wird initialisiert...")

		// Create a new instance of the plugin
		plugin := &liteJoinNotifierPlugin{
			log:        log,
			// HIER EINSTELLUNGEN ANPASSEN:
			apiURL:     "https://example.com/api/player-join", // URL of the API
			timeout:    5 * time.Second,                       // Timeout for API requests
			enabled:    true,                                  // Enable/disable plugin
			retryCount: 3,                                     // Number of retry attempts
			retryDelay: time.Second,                           // Delay between retry attempts
			connTracker: newConnectionTracker(),               // Track connections
		}

		if !plugin.enabled {
			log.Info("Lite Join Notifier Plugin ist deaktiviert.")
			return nil
		}

		// Get config from proxy to check if Lite mode is enabled
		cfg := p.Config().Editions.Java.Config
		if !cfg.Lite.Enabled {
			log.Info("Gate Lite mode is not enabled. This plugin only works with Gate Lite.")
			return nil
		}

		// For Lite mode, we need to intercept connections in a different way
		// Register connection tracker
		plugin.hookIntoConnectionHandling(p)

		log.Info("Lite Join Notifier Plugin erfolgreich initialisiert!",
			"apiURL", plugin.apiURL,
			"timeout", plugin.timeout)
		return nil
	},
}

type liteJoinNotifierPlugin struct {
	log         logr.Logger
	apiURL      string
	timeout     time.Duration
	enabled     bool
	retryCount  int
	retryDelay  time.Duration
	connTracker *connectionTracker
}

// JoinNotification represents the data sent to the API
type JoinNotification struct {
	PlayerName string    `json:"playerName"`
	PlayerUUID string    `json:"playerUUID,omitempty"`
	IPAddress  string    `json:"ipAddress"`
	JoinTime   time.Time `json:"joinTime"`
}

// connectionTracker keeps track of connections to detect joins
type connectionTracker struct {
	mu          sync.Mutex
	connections map[string]connectionInfo
}

type connectionInfo struct {
	username     string
	uuid         uuid.UUID
	virtualHost  string
	connectionTime time.Time
	notified     bool
}

func newConnectionTracker() *connectionTracker {
	return &connectionTracker{
		connections: make(map[string]connectionInfo),
	}
}

// hookIntoConnectionHandling registers our handlers to intercept and track connections
func (p *liteJoinNotifierPlugin) hookIntoConnectionHandling(proxy *proxy.Proxy) {
	// We need to hook into the connection pipeline to detect player logins in Lite mode
	// This requires some modification to the internal handling

	// Override the session handler factory
	originalInitializer := proxy.SessionHandlerInitializer
	if originalInitializer == nil {
		p.log.Info("Could not hook into session handling (initializer is nil)")
		return
	}

	proxy.SessionHandlerInitializer = func(conn netmc.MinecraftConn) {
		// Call the original initializer
		originalInitializer(conn)

		// Add our custom tracker
		p.trackConnection(conn)
	}

	p.log.Info("Successfully hooked into connection handling")
}

// trackConnection monitors a connection for login events
func (p *liteJoinNotifierPlugin) trackConnection(conn netmc.MinecraftConn) {
	// Get the remote address
	remoteAddr := conn.RemoteAddr()
	if remoteAddr == nil {
		return
	}

	clientIP := extractIP(remoteAddr)
	if clientIP == "" {
		return
	}

	// Start a goroutine to monitor this connection
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		connectionID := clientIP
		ctx := conn.Context()

		for {
			select {
			case <-ticker.C:
				// Check connection state
				if conn.Type() == phase.Play {
					// Connection is now in PLAY state, which means login was successful
					// Try to get player info
					if player, ok := getPlayerInfo(conn); ok {
						// We've detected a successful login
						if p.connTracker.registerLogin(connectionID, player) {
							// Only notify if this is the first time for this connection
							p.notifyPlayerJoin(player, clientIP)
						}
					}
				}
				
			case <-ctx.Done():
				// Connection closed
				return
			}
		}
	}()
}

// getPlayerInfo attempts to extract player information from a connection
func getPlayerInfo(conn netmc.MinecraftConn) (map[string]interface{}, bool) {
	result := make(map[string]interface{})

	// Try different ways to get player info in Lite mode
	// 1. Try to get it from the session handler
	handler := conn.ActiveSessionHandler()
	if handler == nil {
		return nil, false
	}

	// Try to extract username, UUID and virtualHost through various methods
	// This depends on the internal structure which might vary
	if usernameProvider, ok := handler.(interface{ Username() string }); ok {
		result["username"] = usernameProvider.Username()
	}

	if uuidProvider, ok := handler.(interface{ PlayerID() uuid.UUID }); ok {
		result["uuid"] = uuidProvider.PlayerID()
	}

	virtualHost := ""
	if vhProvider, ok := handler.(interface{ VirtualHost() string }); ok {
		virtualHost = vhProvider.VirtualHost()
	} else if vhProvider, ok := conn.(interface{ VirtualHost() net.Addr }); ok {
		if vHost := vhProvider.VirtualHost(); vHost != nil {
			virtualHost = vHost.String()
		}
	}
	result["virtualHost"] = virtualHost

	// Check if we have at least a username
	_, hasUsername := result["username"]
	return result, hasUsername
}

// registerLogin registers a successful login and returns true if this is the first notification
func (ct *connectionTracker) registerLogin(connectionID string, playerInfo map[string]interface{}) bool {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	// Check if we've already notified for this connection
	info, exists := ct.connections[connectionID]
	if exists && info.notified {
		return false
	}

	// Update or create connection info
	username, _ := playerInfo["username"].(string)
	playerUUID, _ := playerInfo["uuid"].(uuid.UUID)
	virtualHost, _ := playerInfo["virtualHost"].(string)

	ct.connections[connectionID] = connectionInfo{
		username:     username,
		uuid:         playerUUID,
		virtualHost:  virtualHost,
		connectionTime: time.Now(),
		notified:     true,
	}

	return true
}

// notifyPlayerJoin sends a notification about a player joining
func (p *liteJoinNotifierPlugin) notifyPlayerJoin(playerInfo map[string]interface{}, clientIP string) {
	username, _ := playerInfo["username"].(string)
	playerUUID, _ := playerInfo["uuid"].(uuid.UUID)
	virtualHost, _ := playerInfo["virtualHost"].(string)

	uuidString := ""
	if playerUUID != uuid.Nil {
		uuidString = playerUUID.String()
	}

	// Create notification - simplified version with only required fields
	notification := JoinNotification{
		PlayerName: username,
		PlayerUUID: uuidString,
		IPAddress:  clientIP,
		JoinTime:   time.Now(),
	}

	p.log.Info("Player joined in Lite mode",
		"player", notification.PlayerName,
		"ip", notification.IPAddress,
		"virtualHost", notification.VirtualHost)

	// Send notification asynchronously
	go p.sendNotification(notification)
}

// sendNotification sends a notification to the API
func (p *liteJoinNotifierPlugin) sendNotification(notification JoinNotification) {
	p.log.Info("Sending join notification to API",
		"player", notification.PlayerName,
		"ip", notification.IPAddress)

	jsonData, err := json.Marshal(notification)
	if err != nil {
		p.log.Error(err, "Error serializing notification")
		return
	}

	// Send with retry attempts
	var lastError error
	for attempt := 0; attempt <= p.retryCount; attempt++ {
		if attempt > 0 {
			p.log.Info("Retrying API request", "attempt", attempt, "maxAttempts", p.retryCount)
			time.Sleep(p.retryDelay)
		}

		err = p.doSendRequest(jsonData)
		if err == nil {
			if attempt > 0 {
				p.log.Info("API request successful after retry", "attempts", attempt+1)
			}
			return
		}
		
		lastError = err
		p.log.Error(err, "Error sending API request", "attempt", attempt+1)
	}

	p.log.Error(lastError, "All attempts to send API request failed",
		"player", notification.PlayerName)
}

// doSendRequest performs the actual HTTP request
func (p *liteJoinNotifierPlugin) doSendRequest(jsonData []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", p.apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("error creating HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "LiteJoinNotifier-Plugin/1.0")

	client := &http.Client{
		Timeout: p.timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("API responded with status code %d", resp.StatusCode)
	}

	p.log.Info("Join notification successfully sent",
		"player", string(jsonData))
	return nil
}

// extractIP extracts the IP address from a network address
func extractIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}

	// Try to extract the IP address from different types
	var ipStr string
	switch v := addr.(type) {
	case *net.TCPAddr:
		ipStr = v.IP.String()
	case *net.UDPAddr:
		ipStr = v.IP.String()
	default:
		// Fallback for other address types
		addrStr := addr.String()
		host, _, err := net.SplitHostPort(addrStr)
		if err != nil {
			// If SplitHostPort fails, it could be that addrStr
			// is already just the IP address
			ipStr = addrStr
		} else {
			ipStr = host
		}
	}

	// Validate the IP address
	if net.ParseIP(ipStr) != nil {
		return ipStr
	}
	return ""
}
