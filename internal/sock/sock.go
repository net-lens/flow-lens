package sock

import (
	"context"
	"log"
	"os"
	"sync"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
)

type Sock struct {
	PID int
}

var (
	clientOnce sync.Once
	cdClient   *containerd.Client
	cache      = newPIDCache()
)

func InitContainerdClient() {
	clientOnce.Do(func() {
		sock := os.Getenv("CONTAINERD_SOCKET")
		if sock == "" {
			sock = "/run/containerd/containerd.sock"
		}

		var err error
		cdClient, err = containerd.New(sock)
		if err != nil {
			log.Fatalf("failed to connect to containerd: %v", err)
		}

		SetExistingContainersInfo(context.Background(), cdClient, cache)

		// Start watcher
		go startEventWatcher(context.Background(), cdClient, cache)
	})
}

func (s *Sock) GetContainerInfo(ctx context.Context) (ContainerInfo, error) {

	ctx = namespaces.WithNamespace(ctx, "k8s.io")

	if info, ok := cache.Get(s.PID); ok {
		return info, nil
	}

	log.Printf("[sock] container info not cached yet for pid %d (container may not have started)", s.PID)

	// Not found yet (container may not have started)
	return ContainerInfo{}, nil
}
