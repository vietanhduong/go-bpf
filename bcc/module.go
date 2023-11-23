// Copyright 2016 PLUMgrid
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bcc

import (
	"fmt"
	"log"
	"path"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/vietanhduong/go-bpf/pkg/cpuonline"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc

#include <bcc/bcc_common.h>
#include <bcc/bcc_syms.h>
#include <bcc/libbpf.h>
#include <bcc/bcc_version.h>

#ifndef LIBBCC_VERSION_GEQ
#define LIBBCC_VERSION_GEQ(a, b, c) 0
#endif

int bcc_func_load_wrapper(void *program, int prog_type, const char *name,
						  const struct bpf_insn *insns, int prog_len,
						  const char *license, unsigned kern_version,
						  int log_level, char *log_buf, unsigned log_buf_size,
						  const char *dev_name, int attach_type){

#if LIBBCC_VERSION_GEQ(0, 25, 0)
    return bcc_func_load(program, prog_type, name, insns, prog_len, license,
						 kern_version, log_level, log_buf, log_buf_size,
						 dev_name, attach_type);
#else
    return bcc_func_load(program, prog_type, name, insns, prog_len, license,
						 kern_version, log_level, log_buf, log_buf_size,
						 dev_name);
#endif
}

*/
import "C"

// Module type
type Module struct {
	*ModuleOptions

	p              unsafe.Pointer
	funcs          map[string]int
	kprobes        map[string]int
	uprobes        map[string]int
	tracepoints    map[string]int
	rawTracepoints map[string]int
	perfEvents     map[string][]int
	perfBuffers    map[string]*PerfEvent

	symCacheMu sync.Mutex
	symCaches  map[int]*SymbolCache
}

type compileRequest struct {
	code   string
	cflags []string
	rspCh  chan *Module
}

const (
	BPF_PROBE_ENTRY = iota
	BPF_PROBE_RETURN
)

const (
	XDP_FLAGS_UPDATE_IF_NOEXIST = uint32(1) << iota
	XDP_FLAGS_SKB_MODE
	XDP_FLAGS_DRV_MODE
	XDP_FLAGS_HW_MODE
	XDP_FLAGS_MODES = XDP_FLAGS_SKB_MODE | XDP_FLAGS_DRV_MODE | XDP_FLAGS_HW_MODE
	XDP_FLAGS_MASK  = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_MODES
)

const DEFAULT_PERF_BUFFER_PAGE_CNT = 8

// NewModule constructor
func newModule(code string, opts *ModuleOptions) *Module {
	cflagsC := make([]*C.char, len(opts.CFlags))
	defer func() {
		for _, cflag := range cflagsC {
			C.free(unsafe.Pointer(cflag))
		}
	}()
	for i, cflag := range opts.CFlags {
		cflagsC[i] = C.CString(cflag)
	}
	cs := C.CString(code)
	defer C.free(unsafe.Pointer(cs))
	c := C.bpf_module_create_c_from_string(cs, C.uint(opts.Debug), (**C.char)(&cflagsC[0]), C.int(len(cflagsC)), (C.bool)(opts.AllowRlimit), nil)
	if c == nil {
		return nil
	}
	return &Module{
		ModuleOptions:  opts,
		p:              c,
		funcs:          make(map[string]int),
		kprobes:        make(map[string]int),
		uprobes:        make(map[string]int),
		tracepoints:    make(map[string]int),
		rawTracepoints: make(map[string]int),
		perfEvents:     make(map[string][]int),
		perfBuffers:    make(map[string]*PerfEvent),
		symCaches:      make(map[int]*SymbolCache),
	}
}

// NewModule asynchronously compiles the code, generates a new BPF
// module and returns it.
func NewModule(code string, opt ...ModuleOption) (*Module, error) {
	opts := DefaultModuleOptions()
	for _, o := range opt {
		o(opts)
	}
	var mod *Module
	if mod = newModule(code, opts); mod == nil {
		return nil, fmt.Errorf("failed to compile BPF module")
	}

	if err := mod.autoload(); err != nil {
		return nil, fmt.Errorf("autoload: %w", err)
	}
	return mod, nil
}

func (bpf *Module) autoload() error {
	prefixes := map[string]func(name string) error{
		"kprobe__": func(name string) error {
			fd, err := bpf.LoadKprobe(name)
			if err != nil {
				return fmt.Errorf("load kprobe %s: %w", name, err)
			}
			if err = bpf.AttachKprobe(FixSyscallFnName(name[8:]), fd, -1); err != nil {
				return fmt.Errorf("attach kprobe: %w", err)
			}
			return nil
		},
		"kretprobe__": func(name string) error {
			fd, err := bpf.LoadKprobe(name)
			if err != nil {
				return fmt.Errorf("load kprobe %s: %w", name, err)
			}
			if err = bpf.AttachKretprobe(FixSyscallFnName(name[11:]), fd, -1); err != nil {
				return fmt.Errorf("attach kprobe: %w", err)
			}
			return nil
		},
		"tracepoint__": func(name string) error {
			fd, err := bpf.LoadTracepoint(name)
			if err != nil {
				return fmt.Errorf("load tracepoint %s: %w", name, err)
			}
			tp := strings.ReplaceAll(name[len("tracepoint__"):], "__", ":")
			if err = bpf.AttachTracepoint(tp, fd); err != nil {
				return fmt.Errorf("attach tracepoint: %w", err)
			}
			return nil
		},
		"raw_tracepoint__": func(name string) error {
			fd, err := bpf.LoadRawTracepoint(name)
			if err != nil {
				return fmt.Errorf("load raw tracepoint %s: %w", name, err)
			}
			tp := name[len("raw_tracepoint__"):]
			if err = bpf.AttachRawTracepoint(tp, fd); err != nil {
				return fmt.Errorf("attach raw tracepoint: %w", err)
			}
			return nil
		},
		// TODO(vietanhduong): implement kfunc__, kretfunc__ and lsm__
	}

	var i C.ulong
	for i = 0; i < C.bpf_num_functions(bpf.p); i++ {
		name := C.GoString(C.bpf_function_name(bpf.p, i))
		if fn := prefixes[strings.Split(name, "__")[0]+"__"]; fn != nil {
			if err := fn(name); err != nil {
				return err
			} else {
				log.Printf("Autoload: Loaded function %q", name)
			}
		}
	}
	return nil
}

func (bpf *Module) ReleaseSymCache(pid int) {
	bpf.symCacheMu.Lock()
	defer bpf.symCacheMu.Unlock()
	if pid < 0 {
		pid = -1
	}
	cache, ok := bpf.symCaches[pid]
	if !ok {
		return
	}
	cache.Close()
	delete(bpf.symCaches, pid)
}

func (bpf *Module) GetSymCache(pid int) *SymbolCache {
	bpf.symCacheMu.Lock()
	defer bpf.symCacheMu.Unlock()
	if pid < 0 {
		pid = -1
	}
	cache, ok := bpf.symCaches[pid]
	if !ok {
		cache = NewSymbolCache(pid)
		bpf.symCaches[pid] = cache
	}
	return cache
}

type ResolveSymbolOptions struct {
	ShowOffset bool
	ShowModule bool
	NoDemangle bool
}

// ResolveSymbol Translate a memory address into a function name for a pid, which is returned.
// When the show module option is set, the module name is also included. When the show offset
// is set, the instruction offset as a hexadecimal number is also included in the return string.
// A pid of lss than zero will access the kernel symbol cache.
//
// Example output when both show module and show offset are set:
//
//	"net/http.HandlerFunc.ServeHTTP+0x0000002f [.app]"
//
// Example output when both show module and show offset are unset:
//
//	"net/http.HandlerFunc.ServeHTTP"
func (bpf *Module) ResolveSymbol(pid int, addr uint64, opts ResolveSymbolOptions) string {
	sym := bpf.GetSymCache(pid).Resolve(addr, !opts.NoDemangle)
	if sym == nil || sym.Module == "" {
		return formatAddress(addr)
	}

	var offset string
	var module string
	if sym.Name != "" && opts.ShowOffset {
		offset = fmt.Sprintf("+0x%08x", sym.Offset)
	}
	name := sym.Name
	if name == "" {
		name = "<unknown>"
	}
	name += offset
	if sym.Module != "" && opts.ShowModule {
		module = fmt.Sprintf(" [%s]", path.Base(sym.Module))
	}
	return name + module
}

// ResolveKernelSymbol translate a kernel memory address into a kernel function name, which
// is returned. When the show module is set, the module name ("kernel") is also included.
// When the show offset is set, the instruction offset as a hexadecimal number is also
// included in the string
//
// Example outout when both show module and show offset are set:
//
//	"__x64_sys_epoll_pwait+0x00000077 [kernel]"
func (bpf *Module) ResolveKernelSymbol(addr uint64, opts ResolveSymbolOptions) string {
	return bpf.ResolveSymbol(-1, addr, opts)
}

// ResolveKernelSymbolAddr translate a kernel name into address. This is the reverse of
// ResolveKernelSymbol. This function will return an error if unable to resolve the
// function name.
func (bpf *Module) ResolveKernelSymbolAddr(name string) (uint64, error) {
	return bpf.GetSymCache(-1).ResolveName("", name)
}

// Close takes care of closing all kprobes opened by this modules and
// destroys the underlying libbpf module.
func (bpf *Module) Close() {
	// Destroy BPF module
	C.bpf_module_destroy(bpf.p)
	// detach kprobes
	for k, v := range bpf.kprobes {
		C.bpf_close_perf_event_fd((C.int)(v))
		evNameCS := C.CString(k)
		C.bpf_detach_kprobe(evNameCS)
		C.free(unsafe.Pointer(evNameCS))
	}
	// detach uprobes
	for k, v := range bpf.uprobes {
		C.bpf_close_perf_event_fd((C.int)(v))
		evNameCS := C.CString(k)
		C.bpf_detach_uprobe(evNameCS)
		C.free(unsafe.Pointer(evNameCS))
	}
	// detach tracepoints
	for k, v := range bpf.tracepoints {
		C.bpf_close_perf_event_fd((C.int)(v))
		parts := strings.SplitN(k, ":", 2)
		tpCategoryCS := C.CString(parts[0])
		tpNameCS := C.CString(parts[1])
		C.bpf_detach_tracepoint(tpCategoryCS, tpNameCS)
		C.free(unsafe.Pointer(tpCategoryCS))
		C.free(unsafe.Pointer(tpNameCS))
	}
	// close perf envents
	for _, vs := range bpf.perfEvents {
		for _, v := range vs {
			C.bpf_close_perf_event_fd((C.int)(v))
		}
	}
	// close perf buffers
	for perfName := range bpf.perfBuffers {
		bpf.ClosePerfBuffer(perfName)
	}

	bpf.symCacheMu.Lock()
	// close symbol caches
	for _, cache := range bpf.symCaches {
		cache.Close()
	}
	bpf.symCacheMu.Unlock()

	// close functions
	for _, fd := range bpf.funcs {
		syscall.Close(fd)
	}
}

// GetProgramTag returns a tag for ebpf program under passed fd
func (bpf *Module) GetProgramTag(fd int) (tag uint64, err error) {
	_, err = C.bpf_prog_get_tag(C.int(fd), (*C.ulonglong)(unsafe.Pointer(&tag)))
	return tag, err
}

// LoadNet loads a program of type BPF_PROG_TYPE_SCHED_ACT.
func (bpf *Module) LoadNet(name string, opt ...LoadOption) (int, error) {
	return bpf.Load(name, C.BPF_PROG_TYPE_SCHED_ACT, opt...)
}

// LoadKprobe loads a program of type BPF_PROG_TYPE_KPROBE.
func (bpf *Module) LoadKprobe(name string, opt ...LoadOption) (int, error) {
	return bpf.Load(name, C.BPF_PROG_TYPE_KPROBE, opt...)
}

// LoadTracepoint loads a program of type BPF_PROG_TYPE_TRACEPOINT
func (bpf *Module) LoadTracepoint(name string, opt ...LoadOption) (int, error) {
	return bpf.Load(name, C.BPF_PROG_TYPE_TRACEPOINT, opt...)
}

// LoadRawTracepoint loads a program of type BPF_PROG_TYPE_RAW_TRACEPOINT
func (bpf *Module) LoadRawTracepoint(name string, opt ...LoadOption) (int, error) {
	return bpf.Load(name, C.BPF_PROG_TYPE_RAW_TRACEPOINT, opt...)
}

// LoadPerfEvent loads a program of type BPF_PROG_TYPE_PERF_EVENT
func (bpf *Module) LoadPerfEvent(name string, opt ...LoadOption) (int, error) {
	return bpf.Load(name, C.BPF_PROG_TYPE_PERF_EVENT, opt...)
}

// LoadUprobe loads a program of type BPF_PROG_TYPE_KPROBE.
func (bpf *Module) LoadUprobe(name string, opt ...LoadOption) (int, error) {
	return bpf.Load(name, C.BPF_PROG_TYPE_KPROBE, opt...)
}

// Load a program.
func (bpf *Module) Load(name string, progType int, opt ...LoadOption) (int, error) {
	fd, ok := bpf.funcs[name]
	if ok {
		return fd, nil
	}

	opts := DefaultLoadOptions()
	for _, o := range opt {
		o(opts)
	}
	fd, err := bpf.load(name, progType, opts)
	if err != nil {
		return -1, err
	}
	bpf.funcs[name] = fd
	return fd, nil
}

func (bpf *Module) load(name string, progType int, opts *LoadOptions) (int, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	start := (*C.struct_bpf_insn)(C.bpf_function_start(bpf.p, cname))
	if start == nil {
		return -1, fmt.Errorf("bpf unknown program %s", name)
	}

	var cdevice *C.char
	if opts.Device != "" {
		cdevice = C.CString(opts.Device)
		defer C.free(unsafe.Pointer(&cdevice))
	}

	var loglevel uint
	if bpf.Debug&DEBUG_BPF_REGISTER_STATE != 0 {
		loglevel = 2
	} else if bpf.Debug&DEBUG_BPF != 0 {
		loglevel = 1
	}

	size := C.int(C.bpf_function_size(bpf.p, cname))
	license := C.bpf_module_license(bpf.p)
	version := C.bpf_module_kern_version(bpf.p)

	fd, err := C.bcc_func_load_wrapper(bpf.p, C.int(uint32(progType)), cname, start, size, license, version, C.int(loglevel), nil, 0, cdevice, C.int(opts.AttachType))
	if fd < 0 {
		return -1, fmt.Errorf("load BPF program: %w", err)
	}
	return int(fd), nil
}

var (
	kprobeRegexp = regexp.MustCompile("[+.]")
	uprobeRegexp = regexp.MustCompile("[^a-zA-Z0-9_]")
)

func (bpf *Module) attachProbe(evName string, attachType uint32, fnName string, fd int, maxActive int) error {
	if _, ok := bpf.kprobes[evName]; ok {
		return nil
	}

	evNameCS := C.CString(evName)
	fnNameCS := C.CString(fnName)
	res, err := C.bpf_attach_kprobe(C.int(fd), attachType, evNameCS, fnNameCS, (C.uint64_t)(0), C.int(maxActive))
	C.free(unsafe.Pointer(evNameCS))
	C.free(unsafe.Pointer(fnNameCS))

	if res < 0 {
		return fmt.Errorf("failed to attach BPF kprobe: %v", err)
	}
	bpf.kprobes[evName] = int(res)
	return nil
}

func (bpf *Module) attachUProbe(evName string, attachType uint32, path string, addr uint64, fd, pid int) error {
	evNameCS := C.CString(evName)
	binaryPathCS := C.CString(path)
	res, err := C.bpf_attach_uprobe(C.int(fd), attachType, evNameCS, binaryPathCS, (C.uint64_t)(addr), (C.pid_t)(pid), 0)
	C.free(unsafe.Pointer(evNameCS))
	C.free(unsafe.Pointer(binaryPathCS))

	if res < 0 {
		return fmt.Errorf("failed to attach BPF uprobe: %v", err)
	}
	bpf.uprobes[evName] = int(res)
	return nil
}

// AttachKprobe attaches a kprobe fd to a function.
func (bpf *Module) AttachKprobe(fnName string, fd int, maxActive int) error {
	evName := "p_" + kprobeRegexp.ReplaceAllString(fnName, "_")

	return bpf.attachProbe(evName, BPF_PROBE_ENTRY, fnName, fd, maxActive)
}

// AttachKretprobe attaches a kretprobe fd to a function.
func (bpf *Module) AttachKretprobe(fnName string, fd int, maxActive int) error {
	evName := "r_" + kprobeRegexp.ReplaceAllString(fnName, "_")

	return bpf.attachProbe(evName, BPF_PROBE_RETURN, fnName, fd, maxActive)
}

// AttachTracepoint attaches a tracepoint fd to a function
// The 'name' argument is in the format 'category:name'
func (bpf *Module) AttachTracepoint(name string, fd int) error {
	if _, ok := bpf.tracepoints[name]; ok {
		return nil
	}

	parts := strings.SplitN(name, ":", 2)
	if len(parts) < 2 {
		return fmt.Errorf("failed to parse tracepoint name, expected %q, got %q", "category:name", name)
	}

	tpCategoryCS := C.CString(parts[0])
	tpNameCS := C.CString(parts[1])

	res, err := C.bpf_attach_tracepoint(C.int(fd), tpCategoryCS, tpNameCS)

	C.free(unsafe.Pointer(tpCategoryCS))
	C.free(unsafe.Pointer(tpNameCS))

	if res < 0 {
		return fmt.Errorf("failed to attach BPF tracepoint: %v", err)
	}
	bpf.tracepoints[name] = int(res)
	return nil
}

// AttachRawTracepoint attaches a raw tracepoint fd to a function
// The 'name' argument is in the format 'name', there is no category
func (bpf *Module) AttachRawTracepoint(name string, fd int) error {
	if _, ok := bpf.rawTracepoints[name]; ok {
		return nil
	}

	tpNameCS := C.CString(name)

	res, err := C.bpf_attach_raw_tracepoint(C.int(fd), tpNameCS)

	C.free(unsafe.Pointer(tpNameCS))

	if res < 0 {
		return fmt.Errorf("failed to attach BPF tracepoint: %v", err)
	}
	bpf.rawTracepoints[name] = int(res)
	return nil
}

// AttachPerfEvent attaches a perf event fd to a function
// Argument 'evType' is a member of 'perf_type_id' enum in the kernel
// header 'include/uapi/linux/perf_event.h'. Argument 'evConfig'
// is one of PERF_COUNT_* constants in the same file.
func (bpf *Module) AttachPerfEvent(evType, evConfig int, samplePeriod int, sampleFreq int, pid, cpu, groupFd, fd int) error {
	key := fmt.Sprintf("%d:%d", evType, evConfig)
	if _, ok := bpf.perfEvents[key]; ok {
		return nil
	}

	res := []int{}

	if cpu > 0 {
		r, err := C.bpf_attach_perf_event(C.int(fd), C.uint32_t(evType), C.uint32_t(evConfig), C.uint64_t(samplePeriod), C.uint64_t(sampleFreq), C.pid_t(pid), C.int(cpu), C.int(groupFd))
		if r < 0 {
			return fmt.Errorf("failed to attach BPF perf event: %v", err)
		}

		res = append(res, int(r))
	} else {
		cpus, err := cpuonline.Get()
		if err != nil {
			return fmt.Errorf("failed to determine online cpus: %v", err)
		}

		for _, i := range cpus {
			r, err := C.bpf_attach_perf_event(C.int(fd), C.uint32_t(evType), C.uint32_t(evConfig), C.uint64_t(samplePeriod), C.uint64_t(sampleFreq), C.pid_t(pid), C.int(i), C.int(groupFd))
			if r < 0 {
				return fmt.Errorf("failed to attach BPF perf event: %v", err)
			}

			res = append(res, int(r))
		}
	}

	bpf.perfEvents[key] = res

	return nil
}

// AttachUprobe attaches a uprobe fd to the symbol in the library or binary 'name'
// The 'name' argument can be given as either a full library path (/usr/lib/..),
// a library without the lib prefix, or as a binary with full path (/bin/bash)
// A pid can be given to attach to, or -1 to attach to all processes
//
// Presently attempts to trace processes running in a different namespace
// to the tracer will fail due to limitations around namespace-switching
// in multi-threaded programs (such as Go programs)
func (bpf *Module) AttachUprobe(name, symbol string, fd, pid int) error {
	path, addr, err := resolveSymbolPath(name, symbol, 0x0, pid)
	if err != nil {
		return err
	}
	evName := fmt.Sprintf("p_%s_0x%x", uprobeRegexp.ReplaceAllString(path, "_"), addr)
	return bpf.attachUProbe(evName, BPF_PROBE_ENTRY, path, addr, fd, pid)
}

// AttachMatchingUprobes attaches a uprobe fd to all symbols in the library or binary
// 'name' that match a given pattern.
// The 'name' argument can be given as either a full library path (/usr/lib/..),
// a library without the lib prefix, or as a binary with full path (/bin/bash)
// A pid can be given, or -1 to attach to all processes
//
// Presently attempts to trace processes running in a different namespace
// to the tracer will fail due to limitations around namespace-switching
// in multi-threaded programs (such as Go programs)
func (bpf *Module) AttachMatchingUprobes(name, match string, fd, pid int) error {
	symbols, err := MatchUserSymbols(name, match)
	if err != nil {
		return fmt.Errorf("match user symbols: %w", err)
	}
	if len(symbols) == 0 {
		return fmt.Errorf("no symbols matching %q for %s found", match, name)
	}
	for _, symbol := range symbols {
		if err := bpf.AttachUprobe(name, symbol.Name, fd, pid); err != nil {
			return fmt.Errorf("attach uprobe name=%s function=%s: %w", name, symbol.Name, err)
		}
	}
	return nil
}

// AttachUretprobe attaches a uretprobe fd to the symbol in the library or binary 'name'
// The 'name' argument can be given as either a full library path (/usr/lib/..),
// a library without the lib prefix, or as a binary with full path (/bin/bash)
// A pid can be given to attach to, or -1 to attach to all processes
//
// Presently attempts to trace processes running in a different namespace
// to the tracer will fail due to limitations around namespace-switching
// in multi-threaded programs (such as Go programs)
func (bpf *Module) AttachUretprobe(name, symbol string, fd, pid int) error {
	path, addr, err := resolveSymbolPath(name, symbol, 0x0, pid)
	if err != nil {
		return err
	}
	evName := fmt.Sprintf("r_%s_0x%x", uprobeRegexp.ReplaceAllString(path, "_"), addr)
	return bpf.attachUProbe(evName, BPF_PROBE_RETURN, path, addr, fd, pid)
}

// AttachMatchingUretprobes attaches a uretprobe fd to all symbols in the library or binary
// 'name' that match a given pattern.
// The 'name' argument can be given as either a full library path (/usr/lib/..),
// a library without the lib prefix, or as a binary with full path (/bin/bash)
// A pid can be given, or -1 to attach to all processes
//
// Presently attempts to trace processes running in a different namespace
// to the tracer will fail due to limitations around namespace-switching
// in multi-threaded programs (such as Go programs)
func (bpf *Module) AttachMatchingUretprobes(name, match string, fd, pid int) error {
	symbols, err := MatchUserSymbols(name, match)
	if err != nil {
		return fmt.Errorf("match user symbols: %w", err)
	}
	if len(symbols) == 0 {
		return fmt.Errorf("no symbols matching %s for %s found", match, name)
	}
	for _, symbol := range symbols {
		if err := bpf.AttachUretprobe(name, symbol.Name, fd, pid); err != nil {
			return fmt.Errorf("attach uretprobe name=%s function=%s: %w", name, symbol.Name, err)
		}
	}
	return nil
}

func (bpf *Module) OpenPerfBuffer(name string, cb Callback, pageCnt int) error {
	perfBuf := bpf.perfBuffers[name]
	if perfBuf == nil {
		perfBuf = CreatePerfBuffer(NewTable(bpf.TableId(name), bpf))
		bpf.perfBuffers[name] = perfBuf
	}
	if pageCnt <= 0 {
		pageCnt = DEFAULT_PERF_BUFFER_PAGE_CNT
	}
	return perfBuf.OpenAllCpu(cb, pageCnt)
}

func (bpf *Module) ClosePerfBuffer(name string) error {
	perfBuf := bpf.perfBuffers[name]
	if perfBuf == nil {
		return fmt.Errorf("perf buffer for %s not open", name)
	}
	defer delete(bpf.perfBuffers, name)
	return perfBuf.CloseAllCpu()
}

func (bpf *Module) GetPerfBuffer(name string) *PerfEvent {
	return bpf.perfBuffers[name]
}

func (bpf *Module) PollPerfBuffer(name string, timeout time.Duration) int {
	perfBuf := bpf.perfBuffers[name]
	if perfBuf == nil {
		return -1
	}
	return perfBuf.Poll(timeout)
}

// TableSize returns the number of tables in the module.
func (bpf *Module) TableSize() uint64 {
	size := C.bpf_num_tables(bpf.p)
	return uint64(size)
}

// TableId returns the id of a table.
func (bpf *Module) TableId(name string) C.size_t {
	cs := C.CString(name)
	defer C.free(unsafe.Pointer(cs))
	return C.bpf_table_id(bpf.p, cs)
}

// TableDesc returns a map with table properties (name, fd, ...).
func (bpf *Module) TableDesc(id uint64) map[string]interface{} {
	i := C.size_t(id)
	return map[string]interface{}{
		"name":      C.GoString(C.bpf_table_name(bpf.p, i)),
		"fd":        int(C.bpf_table_fd_id(bpf.p, i)),
		"key_size":  uint64(C.bpf_table_key_size_id(bpf.p, i)),
		"leaf_size": uint64(C.bpf_table_leaf_size_id(bpf.p, i)),
		"key_desc":  C.GoString(C.bpf_table_key_desc_id(bpf.p, i)),
		"leaf_desc": C.GoString(C.bpf_table_leaf_desc_id(bpf.p, i)),
	}
}

// TableIter returns a receveier channel to iterate over entries.
func (bpf *Module) TableIter() <-chan map[string]interface{} {
	ch := make(chan map[string]interface{})
	go func() {
		size := C.bpf_num_tables(bpf.p)
		for i := C.size_t(0); i < size; i++ {
			ch <- bpf.TableDesc(uint64(i))
		}
		close(ch)
	}()
	return ch
}

func (bpf *Module) attachXDP(devName string, fd int, flags uint32) error {
	devNameCS := C.CString(devName)
	res, err := C.bpf_attach_xdp(devNameCS, C.int(fd), C.uint32_t(flags))
	defer C.free(unsafe.Pointer(devNameCS))

	if res != 0 || err != nil {
		return fmt.Errorf("failed to attach BPF xdp to device %v: %v", devName, err)
	}
	return nil
}

// AttachXDP attaches a xdp fd to a device.
func (bpf *Module) AttachXDP(devName string, fd int) error {
	return bpf.attachXDP(devName, fd, 0)
}

// AttachXDPWithFlags attaches a xdp fd to a device with flags.
func (bpf *Module) AttachXDPWithFlags(devName string, fd int, flags uint32) error {
	return bpf.attachXDP(devName, fd, flags)
}

// RemoveXDP removes any xdp from this device.
func (bpf *Module) RemoveXDP(devName string) error {
	return bpf.attachXDP(devName, -1, 0)
}

func GetSyscallFnName(name string) string {
	return GetSyscallPrefix() + name
}

var syscallPrefix string

func GetSyscallPrefix() string {
	if syscallPrefix == "" {
		_, err := bccResolveName("", "__x64_sys_bpf", -1)
		if err == nil {
			syscallPrefix = "__x64_sys_"
		} else {
			syscallPrefix = "sys_"
		}
	}
	return syscallPrefix
}

var syscallPrefixes = []string{
	"sys_",
	"__x64_sys_",
	"__x32_compat_sys_",
	"__ia32_compat_sys_",
	"__arm64_sys_",
	"__s390x_sys_",
	"__s390_sys_",
}

func FixSyscallFnName(name string) string {
	for _, p := range syscallPrefixes {
		if strings.HasPrefix(name, p) {
			return GetSyscallFnName(name[len(p):])
		}
	}

	return name
}
