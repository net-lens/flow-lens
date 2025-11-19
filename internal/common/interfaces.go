package common

import (
	"context"

	"github.com/cilium/ebpf"
)

// EBPFModule is the lifecycle contract for each module.
type EBPFModule interface {
	Load(objFileName string) (*ebpf.Collection, error) // load objects, maps, bpf2go structures
	Attach() error                                     // attach XDP, kprobes, tracepoints, etc
	Run(ctx context.Context) error                     // event loop
	Close() error                                      // close links + objects
}
