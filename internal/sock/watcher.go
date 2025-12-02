package sock

import (
	"context"
	"log"

	"github.com/containerd/containerd"
	eventstypes "github.com/containerd/containerd/api/events"
	tasks "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/events"
	"github.com/containerd/containerd/namespaces"
	typeurl "github.com/containerd/typeurl/v2"
)

func startEventWatcher(ctx context.Context, client *containerd.Client, cache *pidCache) {
	// subscribe to task events
	eventsCh, errCh := client.Subscribe(ctx,
		"topic==\"/tasks/start\"",
		"topic==\"/tasks/exit\"",
	)

	for {
		select {
		case evt := <-eventsCh:
			handleEvent(ctx, client, cache, evt)
		case err, ok := <-errCh:
			if !ok {
				return
			}
			if err != nil {
				log.Printf("[containerd watcher] error: %v", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func handleEvent(ctx context.Context, client *containerd.Client, cache *pidCache, e *events.Envelope) {
	ctx = namespaces.WithNamespace(ctx, e.Namespace)

	switch e.Topic {

	case "/tasks/start":

		var start eventstypes.TaskStart
		if err := typeurl.UnmarshalTo(e.Event, &start); err != nil {
			log.Printf("decode task start: %v", err)
			return
		}

		task, err := client.TaskService().Get(ctx, &tasks.GetRequest{
			ContainerID: start.ContainerID,
		})
		if err != nil {
			log.Println("get task:", err)
			return
		}

		process := task.Process
		if process == nil {
			log.Printf("task process missing for container %s", start.ContainerID)
			return
		}

		ctr, err := client.LoadContainer(ctx, start.ContainerID)
		if err != nil {
			log.Printf("load container: %v", err)
			return
		}

		info, err := ctr.Info(ctx)
		if err != nil {
			log.Printf("container info: %v", err)
			return
		}

		labels := info.Labels

		cache.Set(int(process.Pid), ContainerInfo{
			Namespace:     labels["io.kubernetes.pod.namespace"],
			PodName:       labels["io.kubernetes.pod.name"],
			ContainerName: labels["io.kubernetes.container.name"],
		})

	case "/tasks/exit":
		var exit eventstypes.TaskExit
		if err := typeurl.UnmarshalTo(e.Event, &exit); err != nil {
			log.Printf("decode task exit: %v", err)
			return
		}
		cache.Delete(int(exit.Pid))
	}
}
