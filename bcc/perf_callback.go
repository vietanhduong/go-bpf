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
	"encoding/binary"
	"runtime/cgo"
	"unsafe"
)

type (
	RawCb  func(cookie interface{}, raw []byte, size int32)
	LostCb func(cookie interface{}, lost uint64)
)

var byteOrder binary.ByteOrder

// In lack of binary.HostEndian ...
func init() {
	byteOrder = determineHostByteOrder()
}

// GetHostByteOrder returns the current byte-order.
func GetHostByteOrder() binary.ByteOrder {
	return byteOrder
}

func determineHostByteOrder() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}

// Gateway function as required with CGO Go >= 1.6
// "If a C-program wants a function pointer, a gateway function has to
// be written. This is because we can't take the address of a Go
// function and give that to C-code since the cgo tool will generate a
// stub in C that should be called."
//
//export rawCallback
func rawCallback(cbCookie unsafe.Pointer, raw unsafe.Pointer, rawSize C.int) {
	handler := *(*cgo.Handle)(cbCookie)
	cb := handler.Value().(*callback)
	if cb != nil && cb.raw != nil {
		cb.raw(cb.cookie, C.GoBytes(raw, rawSize), int32(rawSize))
	}
}

//export lostCallback
func lostCallback(cbCookie unsafe.Pointer, lost C.uint64_t) {
	handler := *(*cgo.Handle)(cbCookie)
	cb := handler.Value().(*callback)
	if cb != nil && cb.lost != nil {
		cb.lost(cb.cookie, uint64(lost))
	}
}
