package tcpmonitor

import (
	"github.com/net-lens/flow-lens/internal/common"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	TCPRetransmit = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ebpf",
			Subsystem: "tcp",
			Name:      "retransmit_total",
			Help:      "TCP retransmissions labeled by src/dst addresses",
		},
		[]string{"source_ip", "destination_ip", "source_port", "destination_port", "target_pod", "target_container", "target_namespace"},
	)
)

func init() {
	common.RegisterMetric(TCPRetransmit)
}
