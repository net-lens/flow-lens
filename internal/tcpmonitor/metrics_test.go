package tcpmonitor

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestLabelOrUnknown(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", "unknown"},
		{"pod-a", "pod-a"},
	}

	for _, tt := range tests {
		if got := labelOrUnknown(tt.in); got != tt.want {
			t.Fatalf("labelOrUnknown(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMetricIdentifierRetransmit(t *testing.T) {
	TCPRetransmit.Reset()

	metric := TCPMetric{
		SourceIP:        "10.0.0.1",
		DestinationIP:   "10.0.0.2",
		SourcePort:      "12345",
		DestinationPort: "80",
		TargetPod:       "",
		TargetContainer: "ctr",
		TargetNamespace: "ns",
		Type:            1,
	}

	MetricIdentifier(metric)

	labels := []string{
		metric.SourceIP,
		metric.DestinationIP,
		metric.SourcePort,
		metric.DestinationPort,
		"unknown", // TargetPod empty → unknown
		metric.TargetContainer,
		metric.TargetNamespace,
	}

	if got := testutil.ToFloat64(TCPRetransmit.WithLabelValues(labels...)); got != 1 {
		t.Fatalf("expected counter to be 1, got %v", got)
	}
}

func TestMetricIdentifierIgnoresOtherTypes(t *testing.T) {
	TCPRetransmit.Reset()

	MetricIdentifier(TCPMetric{Type: 0})

	if got := testutil.ToFloat64(TCPRetransmit.WithLabelValues(
		"", "", "", "", "unknown", "unknown", "unknown",
	)); got != 0 {
		t.Fatalf("expected zero increment, got %v", got)
	}
}
