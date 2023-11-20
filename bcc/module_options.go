package bcc

import (
	"fmt"
	"runtime"
	"strings"
)

// Debug flags
// Reference: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-bpf
const (
	DEBUG_LLVM_IR            uint = 0x1  // compiled LLVM IR
	DEBUG_BPF                uint = 0x2  // loaded BPF bytecode and register state on branches
	DEBUG_PREPROCESSOR       uint = 0x4  // pre-processor result
	DEBUG_SOURCE             uint = 0x8  // ASM instructions embedded with source
	DEBUG_BPF_REGISTER_STATE uint = 0x10 // register state on all instructions in addition to DEBUG_BPF
	DEBUG_BTF                uint = 0x20 // print the messages from the libbpf library.
)

type ModuleOptions struct {
	Debug       uint
	CFlags      []string
	AllowRlimit bool
	Device      string
}

type ModuleOption func(*ModuleOptions)

func DefaultModuleOptions() *ModuleOptions {
	return &ModuleOptions{
		CFlags:      []string{fmt.Sprintf("-DNUMCPUS=%d", runtime.NumCPU())},
		AllowRlimit: true,
	}
}

func WithCFlags(cflag ...string) ModuleOption {
	return func(mo *ModuleOptions) {
		if len(cflag) == 0 {
			return
		}
		mo.CFlags = buildCflags(cflag)
	}
}

func WithAllowRlimit(allow bool) ModuleOption {
	return func(mo *ModuleOptions) { mo.AllowRlimit = allow }
}

func WithDebug(mode uint) ModuleOption {
	return func(mo *ModuleOptions) { mo.Debug = mode }
}

func WithDevice(device string) ModuleOption {
	return func(mo *ModuleOptions) { mo.Device = device }
}

func buildCflags(cflags []string) []string {
	var exists bool
	for i := range cflags {
		if strings.HasPrefix(cflags[i], "-DNUMCPUS=") {
			exists = true
			break
		}
	}
	if exists {
		return cflags
	}
	return append(cflags, fmt.Sprintf("-DNUMCPUS=%d", runtime.NumCPU()))
}
