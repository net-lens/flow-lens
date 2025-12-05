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
	State           int // 1 = SYN_SENT, 2 = SYN_RECV, 3 = ESTABLISHED, 4 = FIN_WAIT_1, 5 = FIN_WAIT_2, 6 = CLOSE_WAIT, 7 = CLOSING, 8 = LAST_ACK, 9 = TIME_WAIT, 10 = CLOSED, 11 = LISTEN, 12 = CLOSED_WAIT_2, 13 = CLOSING_2, 14 = LAST_ACK_2, 15 = TIME_WAIT_2, 16 = CLOSED_2
}

const (
	TypeRetrans   = 1
	TypeSendReset = 2
	TypeRecvReset = 3
)

var tcpStateNames = map[int]string{
	1:  "established",
	2:  "syn_sent",
	3:  "syn_recv",
	4:  "fin_wait_1",
	5:  "fin_wait_2",
	6:  "time_wait",
	7:  "close",
	8:  "close_wait",
	9:  "last_ack",
	10: "listen",
	11: "closing",
	12: "new_syn_recv",
	13: "max",
}

func stateLabel(state int) string {
	if name, ok := tcpStateNames[state]; ok {
		return name
	}
	return "unknown"
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
		[]string{
			"source_ip",
			"destination_ip",
			"destination_port",
			"target_pod",
			"target_container",
			"target_namespace",
			"state",
		},
	)

	TCPReset = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "flow_lens",
			Subsystem: "tcp",
			Name:      "reset_total",
			Help:      "TCP resets labeled by src/dst addresses",
		},
		[]string{
			"source_ip",
			"destination_ip",
			"destination_port",
			"target_pod",
			"target_container",
			"target_namespace",
			"state",
			"direction",
		},
	)
)

func MetricIdentifier(tcpMetric TCPMetric) {
	switch tcpMetric.Type {
	case TypeRetrans:
		fmt.Println("TCP retransmission detected")
		TCPRetransmit.WithLabelValues(
			tcpMetric.SourceIP,
			tcpMetric.DestinationIP,
			tcpMetric.DestinationPort,
			labelOrUnknown(tcpMetric.TargetPod),
			labelOrUnknown(tcpMetric.TargetContainer),
			labelOrUnknown(tcpMetric.TargetNamespace),
			stateLabel(tcpMetric.State),
		).Inc()
	case TypeSendReset:
		fmt.Println("TCP send reset detected")
		TCPReset.WithLabelValues(
			tcpMetric.SourceIP,
			tcpMetric.DestinationIP,
			tcpMetric.DestinationPort,
			labelOrUnknown(tcpMetric.TargetPod),
			labelOrUnknown(tcpMetric.TargetContainer),
			labelOrUnknown(tcpMetric.TargetNamespace),
			stateLabel(tcpMetric.State),
			"outbound",
		).Inc()
	case TypeRecvReset:
		fmt.Println("TCP reset detected")
		TCPReset.WithLabelValues(
			tcpMetric.SourceIP,
			tcpMetric.DestinationIP,
			tcpMetric.DestinationPort,
			labelOrUnknown(tcpMetric.TargetPod),
			labelOrUnknown(tcpMetric.TargetContainer),
			labelOrUnknown(tcpMetric.TargetNamespace),
			stateLabel(tcpMetric.State),
			"inbound",
		).Inc()
	}
}

func init() {
	common.RegisterMetric(TCPRetransmit)
	common.RegisterMetric(TCPReset)
}
