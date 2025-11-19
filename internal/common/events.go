package common

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
)

//
// -----------------------------------------------------------------------
//  RING BUFFER POLLING
// -----------------------------------------------------------------------
//

// PollRingbuf reads events from a ring buffer and passes them to handler.
// Handles shutdown via context, and prints lost events if present.
func PollRingbuf(ctx context.Context, rb *ringbuf.Reader, handler func([]byte)) error {
	if rb == nil {
		return fmt.Errorf("nil ringbuf passed to PollRingbuf")
	}

	for {
		select {
		case <-ctx.Done():
			return nil

		default:
			record, err := rb.Read()
			if err != nil {
				// Normal shutdown
				if errors.Is(err, ringbuf.ErrClosed) {
					return nil
				}
				return err
			}

			if len(record.RawSample) == 0 {
				continue
			}
			fmt.Printf("Ringbuf read: %+v\n", record.RawSample)
			handler(record.RawSample)
		}
	}
}

//
// -----------------------------------------------------------------------
//  PERF BUFFER POLLING
// -----------------------------------------------------------------------
//

// PollPerf continuously reads perf event records and calls the handler.
// Gracefully handles shutdown via context and lost samples.
func PollPerf(coll *ebpf.Collection, eventName string, handler func([]byte)) error {

	events, err := perf.NewReader(coll.Maps[eventName], os.Getpagesize())

	if err != nil {
		return fmt.Errorf("create perf reader: %w", err)
	}
	defer events.Close()

	// Channel for signal handling
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	eventsCh := make(chan []byte, 1000)

	go func() {
		for {
			record, err := events.Read()
			if err != nil {
				if perf.IsUnknownEvent(err) {
					continue
				}
				panic(err)
			}
			eventsCh <- record.RawSample
		}
	}()

	go func() {
		for raw := range eventsCh {
			handler(raw)
		}
	}()
	<-sig
	close(eventsCh)
	events.Close()

	return nil
}

//
// -----------------------------------------------------------------------
//  GENERIC EVENT LOOP WRAPPER (Optional)
// -----------------------------------------------------------------------
//
