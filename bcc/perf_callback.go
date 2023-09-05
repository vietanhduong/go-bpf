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
	"sync"
	"unsafe"
)

type (
	ReceiveCallback func([]byte)
	LostCallback    func(uint64)
)

type callbackData struct {
	recvFn ReceiveCallback
	lostFn LostCallback
}

var (
	byteOrder        binary.ByteOrder
	callbackRegister = make(map[uint64]*callbackData)
	callbackIndex    uint64
	mu               sync.Mutex
)

// In lack of binary.HostEndian ...
func init() {
	byteOrder = determineHostByteOrder()
}

func registerCallback(data *callbackData) uint64 {
	mu.Lock()
	defer mu.Unlock()
	callbackIndex++
	for callbackRegister[callbackIndex] != nil {
		callbackIndex++
	}
	callbackRegister[callbackIndex] = data
	return callbackIndex
}

func unregisterCallback(i uint64) {
	mu.Lock()
	defer mu.Unlock()
	delete(callbackRegister, i)
}

func lookupCallback(i uint64) *callbackData {
	return callbackRegister[i]
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
	callbackData := lookupCallback(uint64(uintptr(cbCookie)))
	callbackData.recvFn(C.GoBytes(raw, rawSize))
}

//export lostCallback
func lostCallback(cbCookie unsafe.Pointer, lost C.uint64_t) {
	callbackData := lookupCallback(uint64(uintptr(cbCookie)))
	if callbackData.lostFn != nil {
		callbackData.lostFn(uint64(lost))
	}
}
