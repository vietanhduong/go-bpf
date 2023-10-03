package bcc

import (
	"fmt"
	"log"
	"runtime/cgo"
	"time"
	"unsafe"

	"github.com/vietanhduong/gobpf/pkg/cpuonline"
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

struct epoll_event create_ptr_event(int event_type, void* ptr) {
  struct epoll_event event = { .events = event_type };
  event.data.ptr = ptr;
  return event;
}

void* get_event_data_ptr(struct epoll_event event) { return event.data.ptr; }
*/
import "C"

type callback struct {
	raw    RawCb
	lost   LostCb
	cookie interface{}
}

type PerfBuffer struct {
	table    *Table
	epfd     C.int
	readers  map[int]*C.struct_perf_reader
	handler  cgo.Handle
	epEvents []C.struct_epoll_event
}

func CreatePerfBuffer(table *Table) *PerfBuffer {
	return &PerfBuffer{
		table:   table,
		epfd:    -1,
		readers: make(map[int]*C.struct_perf_reader),
	}
}

func (perf *PerfBuffer) Close() error {
	return perf.CloseAllCpu()
}

func (perf *PerfBuffer) OpenAllCpu(cookie interface{}, rawCb RawCb, lostCb LostCb, pageCnt int) error {
	if len(perf.readers) != 0 || perf.epfd != -1 {
		return fmt.Errorf("perviously opened perf buffer not cleaned")
	}

	cpus, err := cpuonline.Get()
	if err != nil {
		return fmt.Errorf("get online cpu: %v", err)
	}

	perf.handler = cgo.NewHandle(&callback{
		raw:    rawCb,
		lost:   lostCb,
		cookie: cookie,
	})

	perf.epEvents = make([]C.struct_epoll_event, len(cpus))
	perf.epfd = C.epoll_create1(C.EPOLL_CLOEXEC)

	for _, cpu := range cpus {
		opts := &C.struct_bcc_perf_buffer_opts{
			pid:           -1,
			cpu:           C.int(cpu),
			wakeup_events: 1,
		}

		if err := perf.openOnCpu(pageCnt, opts); err != nil {
			_ = perf.CloseAllCpu()
			return err
		}
	}
	return nil
}

func (perf *PerfBuffer) CloseAllCpu() error {
	var errStr string
	perf.handler.Delete()

	if int(perf.epfd) >= 0 {
		_, err := C.close(perf.epfd)
		perf.epfd = -1
		perf.epEvents = perf.epEvents[:0]
		if err != nil {
			errStr += fmt.Sprintf("close epoll: %v\n", err)
		}
	}

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

func (perf *PerfBuffer) Poll(timeout time.Duration) int {
	if perf.epfd < 0 {
		return -1
	}

	timeoutMs := C.int(timeout.Milliseconds())
	cnt, err := C.epoll_wait(perf.epfd, &perf.epEvents[0], C.int(len(perf.readers)), timeoutMs)
	if err != nil {
		log.Printf("epoll_wait: %v", err)
	}

	for i := 0; i < int(cnt); i++ {
		C.perf_reader_event_read((*C.struct_perf_reader)(unsafe.Pointer(C.get_event_data_ptr(perf.epEvents[i]))))
	}
	return int(cnt)
}

func (perf *PerfBuffer) openOnCpu(pageCnt int, opts *C.struct_bcc_perf_buffer_opts) error {
	if _, ok := perf.readers[int(opts.cpu)]; ok {
		return fmt.Errorf("perf buffer already open on CPU %d", opts.cpu)
	}
	if (pageCnt & (pageCnt - 1)) != 0 {
		return fmt.Errorf("pageCnt must be a power of 2: %d", pageCnt)
	}

	reader, err := C.bpf_open_perf_buffer_opts(
		// Raw callback
		(C.perf_reader_raw_cb)(unsafe.Pointer(C.rawCallback)),
		// Lost callback
		(C.perf_reader_lost_cb)(unsafe.Pointer(C.lostCallback)),
		// Callback Cookie
		unsafe.Pointer(&perf.handler),
		C.int(pageCnt), opts,
	)
	if reader == nil {
		return fmt.Errorf("unable to open perf buffer: %v", err)
	}

	readerFd := C.perf_reader_fd(((*C.struct_perf_reader)(reader)))
	if err = perf.table.Update(unsafe.Pointer(&opts.cpu), unsafe.Pointer(&readerFd)); err != nil {
		C.perf_reader_free(unsafe.Pointer(reader))
		return fmt.Errorf("unable to open perf buffer on CPU %d: %v", opts.cpu, err)
	}

	event := C.create_ptr_event(C.EPOLLIN, unsafe.Pointer(reader))
	if _, err = C.epoll_ctl(perf.epfd, C.EPOLL_CTL_ADD, readerFd, &event); err != nil {
		C.perf_reader_free(unsafe.Pointer(reader))
		return fmt.Errorf("unable to add perf buffer FD to epoll: %v", err)
	}

	perf.readers[int(opts.cpu)] = ((*C.struct_perf_reader)(reader))
	return nil
}

func (perf *PerfBuffer) closeOnCpu(cpu int) error {
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
