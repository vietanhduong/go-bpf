package bcc

import (
	"fmt"
	"runtime"
	"runtime/cgo"
	"time"
	"unsafe"

	"github.com/vietanhduong/go-bpf/pkg/cpuonline"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <stdlib.h>
#include <bcc/bcc_common.h>
#include <unistd.h>
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

// TODO(vietanhduong): Implement open perf event
type PerfEvent struct {
	table   *Table
	readers map[int]*C.struct_perf_reader
	handler cgo.Handle
}

func CreatePerfBuffer(table *Table) *PerfEvent {
	return &PerfEvent{
		table:   table,
		readers: make(map[int]*C.struct_perf_reader),
	}
}

func (perf *PerfEvent) Close() error {
	return perf.CloseAllCpu()
}

func (perf *PerfEvent) OpenAllCpu(cb Callback, pageCnt int) error {
	cpus, err := cpuonline.Get()
	if err != nil {
		return fmt.Errorf("get online cpu: %v", err)
	}

	if cb == nil {
		cb = &emptyCallback{}
	}

	perf.handler = cgo.NewHandle(cb)
	runtime.SetFinalizer(perf, (*PerfEvent).Close)

	for _, cpu := range cpus {
		if err := perf.openOnCpu(int(cpu), pageCnt, 1); err != nil {
			_ = perf.CloseAllCpu()
			return err
		}
	}
	return nil
}

func (perf *PerfEvent) CloseAllCpu() error {
	var errStr string
	perf.handler.Delete()

	for cpu := range perf.readers {
		if err := perf.closeOnCpu(cpu); err != nil {
			errStr += fmt.Sprintf("cpu %d: %v\n", cpu, err)
		}
	}

	if errStr != "" {
		return fmt.Errorf("%s", errStr)
	}
	return nil
}

func (perf *PerfEvent) Poll(timeout time.Duration) int {
	ctimeout := C.int(timeout.Milliseconds())

	var readers []*C.struct_perf_reader
	for _, reader := range perf.readers {
		readers = append(readers, reader)
	}
	res := C.perf_reader_poll(C.int(len(readers)), &readers[0], ctimeout)
	return int(res)
}

func (perf *PerfEvent) openOnCpu(cpu, pageCnt, weakupEvents int) error {
	if _, ok := perf.readers[cpu]; ok {
		return fmt.Errorf("perf buffer already open on CPU %d", cpu)
	}
	if (pageCnt & (pageCnt - 1)) != 0 {
		return fmt.Errorf("pageCnt must be a power of 2: %d", pageCnt)
	}

	opts := &C.struct_bcc_perf_buffer_opts{
		pid:           -1,
		cpu:           C.int(cpu),
		wakeup_events: C.int(weakupEvents),
	}

	reader, err := C.bpf_open_perf_buffer_opts(
		// Raw callback
		(C.perf_reader_raw_cb)(unsafe.Pointer(C.rawCallback)),
		// Lost callback
		(C.perf_reader_lost_cb)(unsafe.Pointer(C.lostCallback)),
		// Callback Cookie
		unsafe.Pointer(&perf.handler),
		C.int(pageCnt),
		opts,
	)

	if reader == nil {
		return fmt.Errorf("unable to open perf buffer: %v", err)
	}

	readerFd := C.perf_reader_fd(((*C.struct_perf_reader)(reader)))
	if err = perf.table.Update(unsafe.Pointer(&opts.cpu), unsafe.Pointer(&readerFd)); err != nil {
		C.perf_reader_free(unsafe.Pointer(reader))
		return fmt.Errorf("unable to open perf buffer on CPU %d: %v", opts.cpu, err)
	}

	perf.readers[int(opts.cpu)] = ((*C.struct_perf_reader)(reader))
	return nil
}

func (perf *PerfEvent) closeOnCpu(cpu int) error {
	reader := perf.readers[cpu]
	if reader == nil {
		return nil
	}
	C.perf_reader_free(unsafe.Pointer(reader))
	cpuC := C.int(cpu)
	if err := perf.table.Remove(unsafe.Pointer(&cpuC)); err != nil {
		return fmt.Errorf("unable to close perf buffer on CPU: %d, %v", cpu, err)
	}
	delete(perf.readers, cpu)
	return nil
}
