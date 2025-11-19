package common

import (
	"github.com/cilium/ebpf"
)

// LoadObjects is a simple wrapper to unify object loading.
// For bpf2go, you will usually call LoadXXXObjects directly.
func LoadObjects(objFileName string) (*ebpf.Collection, error) {

	spec, err := ebpf.LoadCollectionSpec(objFileName)
	if err != nil {
		panic(err)
	}

	return ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: 1,
			LogSize:  2 << 20,
		},
	})
}
