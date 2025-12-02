package sock

import (
	"sync"
)

type ContainerInfo struct {
	Namespace     string
	PodName       string
	ContainerName string
}

type pidCache struct {
	mu     sync.RWMutex
	pidMap map[int]ContainerInfo
}

func newPIDCache() *pidCache {
	return &pidCache{
		pidMap: make(map[int]ContainerInfo),
	}
}

func (c *pidCache) Set(pid int, info ContainerInfo) {
	c.mu.Lock()
	c.pidMap[pid] = info
	c.mu.Unlock()
}

func (c *pidCache) Delete(pid int) {
	c.mu.Lock()
	delete(c.pidMap, pid)
	c.mu.Unlock()
}

func (c *pidCache) Get(pid int) (ContainerInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	ci, ok := c.pidMap[pid]
	return ci, ok
}
