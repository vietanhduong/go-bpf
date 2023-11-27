package bcc

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bcc_common.h>
#include <sys/epoll.h>
#include <bcc/libbpf.h>
#include <bcc/perf_reader.h>

// perf_reader_raw_cb and perf_reader_lost_cb as defined in bcc libbpf.h
// typedef void (*perf_reader_raw_cb)(void *cb_cookie, void *raw, int raw_size);
extern void rawCallback(void*, void*, int);
// typedef void (*perf_reader_lost_cb)(void *cb_cookie, uint64_t lost);
extern void lostCallback(void*, uint64_t);

// ringbuf callback
// typedef int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size);
extern int ringbufCallback(void*, void*, size_t);
*/
import "C"

import (
	"runtime/cgo"
	"unsafe"
)

type (
	RawSample     func([]byte, int)
	LostSamples   func(uint64)
	RingbufSample func([]byte, int)
)

type perfCallback struct {
	raw  RawSample
	lost LostSamples
}

// Gateway function as required with CGO Go >= 1.6
// "If a C-program wants a function pointer, a gateway function has to
// be written. This is because we can't take the address of a Go
// function and give that to C-code since the cgo tool will generate a
// stub in C that should be called."
//
//export rawCallback
func rawCallback(cookie unsafe.Pointer, raw unsafe.Pointer, rawSize C.int) {
	handler := *(*cgo.Handle)(cookie)
	if cb, ok := handler.Value().(*perfCallback); ok && cb != nil && cb.raw != nil {
		cb.raw(C.GoBytes(raw, rawSize), int(rawSize))
	}
}

//export lostCallback
func lostCallback(cookie unsafe.Pointer, lost C.uint64_t) {
	handler := *(*cgo.Handle)(cookie)
	if cb, ok := handler.Value().(*perfCallback); ok && cb != nil && cb.lost != nil {
		cb.lost(uint64(lost))
	}
}

//export ringbufCallback
func ringbufCallback(ctx, data unsafe.Pointer, size C.size_t) C.int {
	handler := *(*cgo.Handle)(ctx)
	if cb, ok := handler.Value().(RingbufSample); ok && cb != nil {
		cb(unsafe.Slice((*byte)(data), int(size)), int(size))
	}
	return C.int(0)
}
