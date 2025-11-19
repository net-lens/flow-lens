package common

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	MetricsRegistry = prometheus.NewRegistry()

	countersMu sync.Mutex
	counters   = map[string]*prometheus.CounterVec{}
)

// RegisterMetric remains available for odd cases.
func RegisterMetric(c prometheus.Collector) {
	_ = MetricsRegistry.Register(c)
}

// CounterVecOpts mirrors prometheus.CounterOpts plus label names.
type CounterVecOpts struct {
	Namespace string
	Subsystem string
	Name      string
	Help      string
	Labels    []string
}
