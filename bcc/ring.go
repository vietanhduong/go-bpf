package bcc

import (
	"fmt"
	"runtime/cgo"
	"time"
	"unsafe"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/libbpf.h>

// ringbuf callback
// typedef int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size);
extern int ringbufCallback(void*, void*, size_t);
*/
import "C"

type RingBuf struct {
	table   *Table
	handler cgo.Handle
}

func CreateRingBuf(table *Table) *RingBuf {
	return &RingBuf{
		table: table,
	}
}

func (t *RingBuf) OpenRingBuffer(cb RingbufSample) error {
	if t.table.module.ringManager == nil {
		t.handler = cgo.NewHandle(cb)
		manager, err := C.bpf_new_ringbuf(
			t.table.fd,
			(C.ring_buffer_sample_fn)(unsafe.Pointer(C.ringbufCallback)),
			unsafe.Pointer(&t.handler),
		)
		if err != nil {
			t.handler.Delete()
			return fmt.Errorf("bpf new ringbuf: %w", err)
		}
		t.table.module.ringManager = (*C.struct_ring_buffer)(manager)
		return nil
	}

	t.handler = cgo.NewHandle(cb)
	_, err := C.bpf_add_ringbuf(
		t.table.module.ringManager,
		t.table.fd,
		(C.ring_buffer_sample_fn)(unsafe.Pointer(C.ringbufCallback)),
		unsafe.Pointer(&t.handler),
	)
	if err != nil {
		return fmt.Errorf("bpf add ringbuf: %w", err)
	}
	return nil
}

func (t *RingBuf) Poll(timeout time.Duration) int {
	if t.table.module.ringManager == nil {
		return -1
	}
	if timeout < -1 {
		timeout = -1
	}

	ctimeout := C.int(timeout.Milliseconds())
	res := C.bpf_poll_ringbuf(t.table.module.ringManager, ctimeout)
	return int(res)
}

func (t *RingBuf) Close() {
	if t.handler.Value() != nil {
		t.handler.Delete()
	}
}
