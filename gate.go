package main

import (
	"go.minekube.com/gate/cmd/gate"
	"go.minekube.com/gate/pkg/edition/java/proxy"
	"go.minekube.com/gate/pkg/plugins/ipblacklist"
	"go.minekube.com/gate/pkg/plugins/configdownloader"
	"go.minekube.com/gate/pkg/plugins/antivpn"
	"go.minekube.com/gate/pkg/plugins/nobackendserver"
	"log"
)

func main() {
	// Register plugins
	proxy.Plugins = append(proxy.Plugins,
		ipblacklist.Plugin,
		configdownloader.Plugin,
		antivpn.Plugin,
	)

	// Start Gate proxy in a goroutine
	go func() {
		log.Println("Starting Gate proxy...")
		gate.Execute()
	}()

	// Start the nobackendserver in a goroutine
	go func() {
		log.Println("Starting nobackendserver...")
		nobackendserver.StartServer()
	}()

	// Wait indefinitely to keep both servers running
	select {}
}
