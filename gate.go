package main

import (
	"go.minekube.com/gate/cmd/gate"
	"github.com/minekube/gate-plugin-template/plugins/ipblacklist"
)

func main() {
	proxy.Plugins = append(proxy.Plugins,
        	ipblacklist.Plugin,
    	)
	gate.Execute()
}
