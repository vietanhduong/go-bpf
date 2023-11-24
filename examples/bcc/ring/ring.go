package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/vietanhduong/go-bpf/bcc"
)

import "C"

const source string = `
BPF_RINGBUF_OUTPUT(output, CFG_PAGE_CNT); 

struct data_t {     
	int pid;
	int uid;
	char command[16];
};

int hello(void *ctx) {
	struct data_t data = {}; 

	data.pid = bpf_get_current_pid_tgid() >> 32;
	data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

	bpf_get_current_comm(&data.command, sizeof(data.command));

	output.ringbuf_output(&data, sizeof(data), 0 /* BPF_RB_NO_WAKEUP */); 
	return 0;
}
`

type data struct {
	pid     int32
	uid     int32
	command [16]C.char
}

func main() {
	m, err := bpf.NewModule(source, bpf.WithCFlags(fmt.Sprintf("-DCFG_PAGE_CNT=%d", IntRoudUpToPow2(IntRoundUpAndDivide(1024*1024, os.Getpagesize())))))
	if err != nil {
		log.Printf("Failed to new BPF module: %v", err)
		os.Exit(1)
	}
	defer m.Close()
	log.Printf("Init BPF Module has been completed!")

	fd, err := m.LoadKprobe("hello")
	if err != nil {
		log.Printf("Failed to load kprobe: %v", err)
		os.Exit(1)
	}

	if err = m.AttachKprobe(bpf.GetSyscallFnName("execve"), fd, -1); err != nil {
		log.Printf("Failed to attach  kprobe: %v", err)
		os.Exit(1)
	}

	cb := func(b []byte, size int) {
		d := (*data)(unsafe.Pointer(&b[0]))
		log.Printf("uid=%d pid=%d command=%s", int(d.uid), int(d.pid), C.GoString(&d.command[0]))
	}
	if err = m.OpenRingBuffer("output", cb); err != nil {
		log.Printf("Failed to open ring buffer: %v", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	for {
		select {
		case <-sig:
			return
		default:
		}
		time.Sleep(5 * time.Second)
		m.PollRingBuffer("output", 0)
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
