package joinnotifier

import (
	"github.com/go-logr/logr"
	"go.minekube.com/gate/pkg/gate"
)

// JoinNotifier ist ein einfaches Plugin das Player-Joins loggt
type JoinNotifier struct {
	log logr.Logger
}

// Plugin interface implementation
func (p *JoinNotifier) Init(proxy *gate.Proxy) error {
	p.log = proxy.Logger().WithName("joinnotifier")
	p.log.Info("JoinNotifier plugin initialized")
	
	// Hier könntest du Event-Listener registrieren
	// proxy.Event().Subscribe(...)
	
	return nil
}

// Hier könntest du weitere Plugin-Funktionalität hinzufügen
// z.B. Event-Handler für Player-Joins

// Plugin-Registrierung - wird vom Gate Framework aufgerufen
func New() gate.Plugin {
	return &JoinNotifier{}
}
