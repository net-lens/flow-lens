package tcpmonitor

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/net-lens/flow-lens/internal/common"
)

// Manager wires together loading, attaching, and closing for the tcp monitor BPF programs.
type Manager struct {
	Collection         *ebpf.Collection
	tpV4ConnectLink    link.Link
	tpRetransmitLink   link.Link
	tpV4ConnectRetLink link.Link
}

type Event struct {
	Timestamp uint64
	PID       uint32
	Sport     uint16
	Dport     uint16
	Saddr     [4]byte
	Daddr     [4]byte
	SaddrV6   [16]byte
	DaddrV6   [16]byte
	Family    uint16
	State     int32
	Netns     uint32
}

// Load opens the BPF object and validates that required programs exist.
func (m *Manager) Load(objFileName string) error {
	coll, err := common.LoadObjects(objFileName)
	if err != nil {
		return err
	}

	if coll.Programs["tracepoint__tcp__tcp_retransmit_skb"] == nil {
		coll.Close()
		return fmt.Errorf("missing required tcp tracepoint programs in %s", objFileName)
	}

	m.Collection = coll
	return nil
}

// Attach binds the tracepoint programs and keeps the links for cleanup.
func (m *Manager) Attach() error {
	if m.Collection == nil {
		return fmt.Errorf("collection not loaded")
	}

	connectProg := m.Collection.Programs["bpf_tcp_v4_connect"]
	connectRetProg := m.Collection.Programs["bpf_ret_tcp_v4_connect"]
	retransProg := m.Collection.Programs["tracepoint__tcp__tcp_retransmit_skb"]

	tpV4Connect, err := common.AttachKprobe("tcp_v4_connect", connectProg)
	if err != nil {
		return err
	}

	tpV4ConnectRetLink, err := common.AttachKretprobe("tcp_v4_connect", connectRetProg)
	if err != nil {
		tpV4Connect.Close()
		return err
	}

	tpRetransmit, err := common.AttachTracepoint("tcp", "tcp_retransmit_skb", retransProg)
	if err != nil {
		tpV4Connect.Close()
		return err
	}

	m.tpV4ConnectLink = tpV4Connect
	m.tpRetransmitLink = tpRetransmit
	m.tpV4ConnectRetLink = tpV4ConnectRetLink
	return nil
}

func (m *Manager) Run(ctx context.Context) error {
	if m.Collection == nil {
		return fmt.Errorf("collection not loaded")
	}
	fmt.Println("TCP monitor running")

	handler := func(data []byte) {
		var evt Event
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
			panic(err)
		}
		var srcIP, dstIP string

		switch evt.Family {
		case 2: // AF_INET
			srcIP = net.IP(evt.Saddr[:]).String()
			dstIP = net.IP(evt.Daddr[:]).String()
		case 10: // AF_INET6
			srcIP = net.IP(evt.SaddrV6[:]).String()
			dstIP = net.IP(evt.DaddrV6[:]).String()
		}

		pod_name := "test-pod"
		container_name := "test-container"
		namespace := "test-namespace"

		TCPRetransmit.WithLabelValues(
			srcIP, dstIP, strconv.Itoa(int(evt.Sport)), strconv.Itoa(int(evt.Dport)), pod_name, container_name, namespace,
		).Inc()

		fmt.Printf("TCP retransmission: %+v\n", evt.PID)

	}

	return common.PollPerf(m.Collection, "events", handler)
}

// Close detaches links and closes the collection.
func (m *Manager) Close() error {
	var firstErr error

	if m.tpV4ConnectLink != nil {
		if err := m.tpV4ConnectLink.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.tpV4ConnectLink = nil
	}

	if m.tpRetransmitLink != nil {
		if err := m.tpRetransmitLink.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.tpRetransmitLink = nil
	}

	if m.tpV4ConnectRetLink != nil {
		if err := m.tpV4ConnectRetLink.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.tpV4ConnectRetLink = nil
	}

	if m.Collection != nil {
		m.Collection.Close()
	}

	return nil
}
