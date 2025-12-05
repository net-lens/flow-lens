package tcpmonitor

import (
	"fmt"

	"github.com/net-lens/flow-lens/internal/common"
	"github.com/prometheus/client_golang/prometheus"
)

type TCPMetric struct {
	SourceIP        string
	DestinationIP   string
	SourcePort      string
	DestinationPort string
	TargetPod       string
	TargetContainer string
	TargetNamespace string
	Type            int // 1 = RETRANS
}

func labelOrUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

var (
	TCPRetransmit = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "flow_lens",
			Subsystem: "tcp",
			Name:      "retransmit_total",
			Help:      "TCP retransmissions labeled by src/dst addresses",
		},
		[]string{"source_ip", "destination_ip", "source_port", "destination_port", "target_pod", "target_container", "target_namespace"},
	)
)

func MetricIdentifier(tcpMetric TCPMetric) {
	switch tcpMetric.Type {
	case 1:
		fmt.Println("TCP retransmission detected")
		TCPRetransmit.WithLabelValues(
			tcpMetric.SourceIP,
			tcpMetric.DestinationIP,
			tcpMetric.SourcePort,
			tcpMetric.DestinationPort,
			labelOrUnknown(tcpMetric.TargetPod),
			labelOrUnknown(tcpMetric.TargetContainer),
			labelOrUnknown(tcpMetric.TargetNamespace),
		).Inc()
	}
}

func init() {
	common.RegisterMetric(TCPRetransmit)
}
