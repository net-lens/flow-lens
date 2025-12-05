package sock

import (
	"context"
	"testing"
)

func TestSockGetContainerInfoHit(t *testing.T) {
	originalCache := cache
	cache = newPIDCache()
	t.Cleanup(func() { cache = originalCache })

	expected := ContainerInfo{Namespace: "ns", PodName: "pod", ContainerName: "ctr"}
	cache.Set(999, expected)

	s := &Sock{PID: 999}
	got, err := s.GetContainerInfo(context.Background())
	if err != nil {
		t.Fatalf("GetContainerInfo returned error: %v", err)
	}
	if got != expected {
		t.Fatalf("expected %+v, got %+v", expected, got)
	}
}

func TestSockGetContainerInfoMiss(t *testing.T) {
	originalCache := cache
	cache = newPIDCache()
	t.Cleanup(func() { cache = originalCache })

	s := &Sock{PID: 111}
	got, err := s.GetContainerInfo(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != (ContainerInfo{}) {
		t.Fatalf("expected zero ContainerInfo on miss, got %+v", got)
	}
}
