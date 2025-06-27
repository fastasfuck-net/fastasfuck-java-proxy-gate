package joinnotifier

import (
	"context"
	"github.com/go-logr/logr"
	"go.minekube.com/gate/pkg/edition/java/proxy"
)

// Plugin ist die Variable die von gate.go erwartet wird
var Plugin = proxy.Plugin{
	Name: "JoinNotifier",
	Init: func(ctx context.Context, p *proxy.Proxy) error {
		log := logr.FromContextOrDiscard(ctx)
		log.Info("JoinNotifier Plugin loaded (placeholder)")
		
		// TODO: Hier könntest du später echte Join-Notification-Logik hinzufügen
		// z.B. Event-Subscriptions für Player-Joins
		
		return nil
	},
}
