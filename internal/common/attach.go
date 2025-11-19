package common

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//
// -----------------------------------------------------------------------
//  XDP ATTACH
// -----------------------------------------------------------------------
//

// AttachXDP attaches an XDP program to an interface by name.
// Example: ln, _ := AttachXDP("eth0", objs.XdpProg)
func AttachXDP(iface string, prog *ebpf.Program) (link.Link, error) {
	if prog == nil {
		return nil, fmt.Errorf("xdp attach: nil program")
	}

	ifIndex, err := ResolveInterfaceIndex(iface)
	if err != nil {
		return nil, err
	}

	ln, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifIndex,
		Flags:     link.XDPGenericMode, // Change to XDPDriverMode if supported
	})
	if err != nil {
		return nil, fmt.Errorf("attach xdp: %w", err)
	}

	return ln, nil
}

//
// -----------------------------------------------------------------------
//  KPROBE / KRETPROBE
// -----------------------------------------------------------------------
//

// AttachKprobe attaches a kprobe.
func AttachKprobe(symbol string, prog *ebpf.Program) (link.Link, error) {
	if prog == nil {
		return nil, fmt.Errorf("kprobe attach: nil program")
	}
	ln, err := link.Kprobe(symbol, prog, nil)
	if err != nil {
		return nil, fmt.Errorf("attach kprobe %s: %w", symbol, err)
	}
	return ln, nil
}

// AttachKretprobe attaches a kretprobe.
func AttachKretprobe(symbol string, prog *ebpf.Program) (link.Link, error) {
	if prog == nil {
		return nil, fmt.Errorf("kretprobe attach: nil program")
	}
	ln, err := link.Kretprobe(symbol, prog, nil)
	if err != nil {
		return nil, fmt.Errorf("attach kretprobe %s: %w", symbol, err)
	}
	return ln, nil
}

//
// -----------------------------------------------------------------------
//  TRACEPOINT
// -----------------------------------------------------------------------
//

// AttachTracepoint attaches to a kernel tracepoint.
func AttachTracepoint(category, name string, prog *ebpf.Program) (link.Link, error) {
	if prog == nil {
		return nil, fmt.Errorf("tracepoint attach: nil program")
	}
	ln, err := link.Tracepoint(category, name, prog, nil)
	if err != nil {
		return nil, fmt.Errorf("attach tracepoint %s/%s: %w", category, name, err)
	}
	return ln, nil
}

//
// -----------------------------------------------------------------------
//  INTERFACE UTILS
// -----------------------------------------------------------------------
//

// ResolveInterfaceIndex converts "eth0" → 2, etc.
func ResolveInterfaceIndex(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("resolve iface %s: %w", name, err)
	}
	return iface.Index, nil
}
