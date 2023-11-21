package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/vietanhduong/go-bpf/bcc"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc

#include <linux/perf_event.h>
#include <bcc/libbpf.h>
#include <bcc/perf_reader.h>

struct key_t {
  uint32_t pid;
  int user_stack_id;
  int kernel_stack_id;
};
*/
import "C"

const source string = `
#include <linux/bpf_perf_event.h>
#include <linux/ptrace.h>

const int TOTAL_ENTRIES = 65536;

struct key_t {
  uint32_t pid;
  int user_stack_id;
  int kernel_stack_id;
};

BPF_STACK_TRACE(stack_traces, TOTAL_ENTRIES);
BPF_PERF_OUTPUT(histogram);

int do_perf_event(struct bpf_perf_event_data *ctx) {
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t pid = id;

  struct key_t key = {};
  key.pid = tgid;
  key.kernel_stack_id = stack_traces.get_stackid(&ctx->regs, 0);
  key.user_stack_id = stack_traces.get_stackid(&ctx->regs, BPF_F_USER_STACK);
  histogram.perf_submit(ctx, &key, sizeof(key));
  return 0;
}
`

type key struct {
	pid           uint32
	userStackId   int32
	kernelStackId int32
}

func pow(x int) int {
	power := 1
	for power < x {
		power *= 2
	}
	return power
}

func main() {
	var pid int
	var sleep int
	flag.IntVar(&pid, "pid", -1, "PID")
	flag.IntVar(&sleep, "sleep", 30, "Sleep")
	flag.Parse()

	if pid == -1 {
		log.Printf("-pid is required")
		os.Exit(1)
	}

	m, err := bcc.NewModule(source)
	if err != nil {
		panic(err)
	}
	defer m.Close()

	fd, err := m.LoadPerfEvent("do_perf_event")
	if err != nil {
		log.Printf("load perf event failed: %v", err)
		os.Exit(1)
	}

	if err = m.AttachPerfEvent(1, 0, 11, 0, -1, -1, -1, fd); err != nil {
		log.Printf("attach perf event failed: %v", err)
		os.Exit(1)
	}

	log.Printf("attached perf event!")

	if sleep < 0 {
		sleep = 30
	}

	aggregate := func() []*key {
		cb := newCb(pid)
		pageCnt := IntRoudUpToPow2(IntRoundUpAndDivide(1024*1024, os.Getpagesize()))

		err := m.OpenPerfBuffer("histogram", cb, pageCnt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
			os.Exit(1)
		}

		done := time.After(time.Duration(sleep) * time.Second)
		<-done
		m.PollPerfBuffer("histogram", 0)
		log.Printf("Total stack: %v", cb.counter)
		return cb.stacks
	}
	stacks := aggregate()
	log.Printf("preparing to aggregate stack...")

	stackTable := bcc.NewTable(m.TableId("stack_traces"), m)

	all := make(map[string]int)
	for _, stack := range stacks {
		var symbols []string
		if stack.userStackId > 0 {
			addrs := stackTable.GetStackAddr(int(stack.userStackId), true)
			for _, addr := range addrs {
				symbols = append(symbols, m.ResolveSymbol(pid, addr, bcc.ResolveSymbolOptions{}))
			}
		}

		if stack.kernelStackId > 0 {
			addrs := stackTable.GetStackAddr(int(stack.kernelStackId), true)
			for _, addr := range addrs {
				sym := m.ResolveKernelSymbol(addr, bcc.ResolveSymbolOptions{ShowModule: true})
				symbols = append(symbols, sym)
			}
		}

		if len(symbols) != 0 {
			all[strings.Join(symbols, ";")]++
		}
	}

	for k, v := range all {
		log.Printf("%s: %v", k, v)
	}
}

func IntRoundUpAndDivide(x, y int) int {
	return (x + (y - 1)) / y
}

func IntRoudUpToPow2(x int) int {
	var power int = 1
	for power < x {
		power *= 2
	}
	return power
}

type stackTraceCb struct {
	counter int
	stacks  []*key
	pid     int
}

func newCb(pid int) *stackTraceCb {
	return &stackTraceCb{pid: pid}
}

func (t *stackTraceCb) RawSample(raw []byte, size int32) {
	stack := (*key)(unsafe.Pointer(&raw[0]))
	if stack.pid == uint32(t.pid) {
		t.counter++
		t.stacks = append(t.stacks, stack)
	}
}

func (t *stackTraceCb) LostSamples(lost uint64) {}
