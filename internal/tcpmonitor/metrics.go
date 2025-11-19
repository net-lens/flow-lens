package tcpmonitor

import (
	"github.com/net-lens/flow-lens/internal/common"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	TCPConnect = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ebpf",
			Subsystem: "tcp",
			Name:      "connect_total",
			Help:      "TCP connect attempts labeled by src/dst addresses",
		},
		[]string{"src", "dst", "sport", "dport", "target_pod", "target_container", "target_namespace"},
	)

	TCPRetransmit = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ebpf",
			Subsystem: "tcp",
			Name:      "retransmit_total",
			Help:      "TCP retransmissions labeled by src/dst addresses",
		},
		[]string{"src", "dst", "sport", "dport", "target_pod", "target_container", "target_namespace"},
	)
)

func init() {
	common.RegisterMetric(TCPConnect)
	common.RegisterMetric(TCPRetransmit)
}
