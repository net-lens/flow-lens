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

// GetOrCreateCounterVec returns a CounterVec tied to MetricsRegistry.
// Subsequent calls with the same fully-qualified name reuse the existing vector.
func GetOrCreateCounterVec(opts CounterVecOpts) *prometheus.CounterVec {
	fqName := prometheus.BuildFQName(opts.Namespace, opts.Subsystem, opts.Name)

	countersMu.Lock()
	defer countersMu.Unlock()

	if cv, ok := counters[fqName]; ok {
		return cv
	}

	cv := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: opts.Namespace,
			Subsystem: opts.Subsystem,
			Name:      opts.Name,
			Help:      opts.Help,
		},
		opts.Labels,
	)

	_ = MetricsRegistry.Register(cv)
	counters[fqName] = cv
	return cv
}
