package blacklist

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/go-logr/logr"
)

var (
	globalBlacklist *Blacklist
	routeBlacklist  *RouteBlacklist
	ipCheckFuncs    []IPCheckFunc
	mutex           sync.RWMutex
	logger          logr.Logger
)

// IPCheckFunc ist eine Funktion, die prüft, ob eine IP blockiert ist
type IPCheckFunc func(ipAddr string) bool

// RegisterIPCheckFunc registriert eine Funktion zum Überprüfen von IP-Adressen
func RegisterIPCheckFunc(fn IPCheckFunc) {
	mutex.Lock()
	defer mutex.Unlock()
	ipCheckFuncs = append(ipCheckFuncs, fn)
}

// CheckIP prüft, ob eine IP durch eine der registrierten Funktionen blockiert ist
func CheckIP(ipAddr string) bool {
	mutex.RLock()
	defer mutex.RUnlock()
	for _, fn := range ipCheckFuncs {
		if fn(ipAddr) {
			return true
		}
	}
	return false
}

// Blacklist repräsentiert eine Sammlung blockierter IP-Adressen
type Blacklist struct {
	ips     map[string]bool
	mu      sync.RWMutex
	path    string
	watcher *fsnotify.Watcher
}

// NewBlacklist erstellt eine neue Blacklist aus einer JSON-Datei
func NewBlacklist(path string) (*Blacklist, error) {
	b := &Blacklist{
		ips:  make(map[string]bool),
		path: path,
	}

	err := b.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load blacklist from %s: %w", path, err)
	}

	return b, nil
}

// Load lädt die Blacklist aus einer Datei
func (b *Blacklist) Load() error {
	data, err := os.ReadFile(b.path)
	if err != nil {
		// Wenn die Datei nicht existiert, erstellen wir eine leere
		if os.IsNotExist(err) {
			b.mu.Lock()
			b.ips = make(map[string]bool)
			b.mu.Unlock()
			return nil
		}
		return fmt.Errorf("error reading blacklist file: %w", err)
	}

	var ips []string
	if err := json.Unmarshal(data, &ips); err != nil {
		return fmt.Errorf("error parsing blacklist JSON: %w", err)
	}

	newIPs := make(map[string]bool)
	for _, ip := range ips {
		newIPs[ip] = true
	}

	b.mu.Lock()
	b.ips = newIPs
	b.mu.Unlock()

	return nil
}

// Contains prüft, ob eine IP in der Blacklist enthalten ist
func (b *Blacklist) Contains(ip string) bool {
	if b == nil {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.ips[ip]
}

// Cleanup bereinigt abgelaufene oder ungültige Einträge
func (b *Blacklist) Cleanup() {
	// Hier könnten wir zum Beispiel temporäre Einträge entfernen
	// In dieser einfachen Implementierung tun wir nichts
}

// RouteBlacklist repräsentiert eine Sammlung von blockierten IP-Adressen pro Route
type RouteBlacklist struct {
	routes  map[string]map[string]bool
	mu      sync.RWMutex
	path    string
	watcher *fsnotify.Watcher
}

// NewRouteBlacklist erstellt eine neue RouteBlacklist aus einer JSON-Datei
func NewRouteBlacklist(path string) (*RouteBlacklist, error) {
	rb := &RouteBlacklist{
		routes: make(map[string]map[string]bool),
		path:   path,
	}

	err := rb.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load route blacklist from %s: %w", path, err)
	}

	return rb, nil
}

// Load lädt die RouteBlacklist aus einer Datei
func (rb *RouteBlacklist) Load() error {
	data, err := os.ReadFile(rb.path)
	if err != nil {
		// Wenn die Datei nicht existiert, erstellen wir eine leere
		if os.IsNotExist(err) {
			rb.mu.Lock()
			rb.routes = make(map[string]map[string]bool)
			rb.mu.Unlock()
			return nil
		}
		return fmt.Errorf("error reading route blacklist file: %w", err)
	}

	var routes map[string][]string
	if err := json.Unmarshal(data, &routes); err != nil {
		return fmt.Errorf("error parsing route blacklist JSON: %w", err)
	}

	newRoutes := make(map[string]map[string]bool)
	for route, ips := range routes {
		newRoutes[route] = make(map[string]bool)
		for _, ip := range ips {
			newRoutes[route][ip] = true
		}
	}

	rb.mu.Lock()
	rb.routes = newRoutes
	rb.mu.Unlock()

	return nil
}

// Contains prüft, ob eine IP für eine Route blockiert ist
func (rb *RouteBlacklist) Contains(route, ip string) bool {
	if rb == nil {
		return false
	}
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	routeMap, ok := rb.routes[route]
	if !ok {
		return false
	}
	return routeMap[ip]
}

// Initialisiert die globalen Blacklists und richtet eine Überwachung ein
func InitBlacklist(globalPath, routePath string) error {
	var err error

	// Erstelle die Blacklists
	globalBlacklist, err = NewBlacklist(globalPath)
	if err != nil {
		return fmt.Errorf("failed to create global blacklist: %w", err)
	}

	routeBlacklist, err = NewRouteBlacklist(routePath)
	if err != nil {
		return fmt.Errorf("failed to create route blacklist: %w", err)
	}

	// Erstelle einen File-Watcher für die Blacklists
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	// Überwache die Blacklist-Dateien
	if err := watcher.Add(globalPath); err != nil {
		// Ignoriere den Fehler, wenn die Datei nicht existiert
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to watch global blacklist file: %w", err)
		}
	}

	if err := watcher.Add(routePath); err != nil {
		// Ignoriere den Fehler, wenn die Datei nicht existiert
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to watch route blacklist file: %w", err)
		}
	}

	go watchFiles(watcher, globalPath, routePath)

	// Registriere eine Standardprüffunktion
	RegisterIPCheckFunc(func(ip string) bool {
		return globalBlacklist.Contains(ip)
	})

	return nil
}

// Überwacht die Blacklist-Dateien und lädt sie neu, wenn sie sich ändern
func watchFiles(watcher *fsnotify.Watcher, globalPath, routePath string) {
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				if event.Name == globalPath {
					if err := globalBlacklist.Load(); err != nil {
						if logger != nil {
							logger.Error(err, "Failed to reload global blacklist")
						}
					}
				} else if event.Name == routePath {
					if err := routeBlacklist.Load(); err != nil {
						if logger != nil {
							logger.Error(err, "Failed to reload route blacklist")
						}
					}
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			if logger != nil {
				logger.Error(err, "Error watching blacklist files")
			}
		}
	}
}

// SetLogger setzt den Logger für das Blacklist-Paket
func SetLogger(log logr.Logger) {
	logger = log
}
