package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/net-lens/flow-lens/internal/common"
	"github.com/net-lens/flow-lens/internal/tcpmonitor"

	"github.com/cilium/ebpf"
	"github.com/net-lens/flow-lens/internal/sock"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

	metricsAddr := os.Getenv("METRICS_ADDR")
	if metricsAddr == "" {
		metricsAddr = ":2112"
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(common.MetricsRegistry, promhttp.HandlerOpts{}))

	metricsSrv := &http.Server{
		Addr:    metricsAddr,
		Handler: mux,
	}

	sock.InitContainerdClient()

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

	go func() {
		log.Printf("Prometheus metrics listening on %s/metrics", metricsAddr)
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("metrics server failed: %v", err)
			cancel()
		}
	}()

	<-ctx.Done()
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := metricsSrv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("metrics server shutdown error: %v", err)
	}
	shutdownCancel()

	for _, m := range modules {
		if err := m.mod.Close(); err != nil {
			log.Printf("%s close failed: %v", m.name, err)
		}
	}

	wg.Wait()
}
