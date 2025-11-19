package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/net-lens/flow-lens/internal/tcpmonitor"

	"github.com/cilium/ebpf"
)

type module interface {
	Load(string) error
	Attach() error
	Run(context.Context) error
	Close() error
}

type moduleSpec struct {
	name string
	obj  string
	mod  module
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	modules := []moduleSpec{
		{
			name: "tcpmonitor",
			obj:  "./bpf/tcpmonitor/tcp_monitor.o",
			mod:  &tcpmonitor.Manager{},
		},
	}

	for _, m := range modules {
		if err := m.mod.Load(m.obj); err != nil {
			var verr *ebpf.VerifierError
			if errors.As(err, &verr) {
				log.Printf("verifier log:\n%s", verr.Log)
			}
			log.Fatalf("%s load failed: %v", m.name, err)
		}
		if err := m.mod.Attach(); err != nil {
			log.Fatalf("%s attach failed: %v", m.name, err)
		}
	}

	var wg sync.WaitGroup
	for _, m := range modules {
		wg.Add(1)
		go func(ms moduleSpec) {
			defer wg.Done()
			if err := ms.mod.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("%s run failed: %v", ms.name, err)
				cancel()
			}
		}(m)
	}

	<-ctx.Done()
	cancel()

	for _, m := range modules {
		if err := m.mod.Close(); err != nil {
			log.Printf("%s close failed: %v", m.name, err)
		}
	}

	wg.Wait()
}
