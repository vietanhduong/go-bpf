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

*/
import "C"

import (
	"runtime/cgo"
	"unsafe"
)

type Callback interface {
	RawSample(raw []byte, size int32)
	LostSamples(lost uint64)
}

type emptyCallback struct{}

var _ Callback = (*emptyCallback)(nil)

func (*emptyCallback) RawSample([]byte, int32) {}
func (*emptyCallback) LostSamples(uint64)      {}

// Gateway function as required with CGO Go >= 1.6
// "If a C-program wants a function pointer, a gateway function has to
// be written. This is because we can't take the address of a Go
// function and give that to C-code since the cgo tool will generate a
// stub in C that should be called."
//
//export rawCallback
func rawCallback(cookie unsafe.Pointer, raw unsafe.Pointer, rawSize C.int) {
	handler := *(*cgo.Handle)(cookie)
	if cb, ok := handler.Value().(Callback); ok && cb != nil {
		cb.RawSample(C.GoBytes(raw, rawSize), int32(rawSize))
	}
}

//export lostCallback
func lostCallback(cookie unsafe.Pointer, lost C.uint64_t) {
	handler := *(*cgo.Handle)(cookie)
	if cb, ok := handler.Value().(Callback); ok && cb != nil {
		cb.LostSamples(uint64(lost))
	}
}
