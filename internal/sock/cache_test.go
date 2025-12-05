package sock

import (
	"sync"
	"testing"
)

func TestPIDCacheSetGetDelete(t *testing.T) {
	cache := newPIDCache()
	info := ContainerInfo{Namespace: "ns", PodName: "pod", ContainerName: "ctr"}

	cache.Set(123, info)

	got, ok := cache.Get(123)
	if !ok || got != info {
		t.Fatalf("expected cache hit with %+v, got %+v (ok=%v)", info, got, ok)
	}

	cache.Delete(123)

	if _, ok := cache.Get(123); ok {
		t.Fatalf("expected cache miss after delete")
	}
}

func TestPIDCacheConcurrentAccess(t *testing.T) {
	cache := newPIDCache()
	info := ContainerInfo{}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(pid int) {
			defer wg.Done()
			cache.Set(pid, info)
			cache.Get(pid)
			cache.Delete(pid)
		}(i)
	}
	wg.Wait()
}
