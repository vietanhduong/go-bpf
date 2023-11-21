// Copyright 2017 Louis McCormack
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
	"regexp"
	"runtime/cgo"
	"unsafe"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
#include <bcc/bcc_syms.h>
#include <bcc/bcc_elf.h>
#include <linux/bpf.h>
#include <linux/elf.h>

extern int symCallback(char*, uint64_t, uint64_t, void*);
*/
import "C"

type SymbolCache struct {
	pid   int
	cache unsafe.Pointer
}

func NewSymbolCache(pid int) *SymbolCache {
	return &SymbolCache{pid, initSymbolCache(pid)}
}

func initSymbolCache(pid int) unsafe.Pointer {
	if pid < 0 {
		pid = -1
	}
	opt := (*C.struct_bcc_symbol_option)(unsafe.Pointer(&C.struct_bcc_symbol_option{
		use_debug_file:       C.int(boolToInt(false)),
		check_debug_file_crc: C.int(boolToInt(false)),
		lazy_symbolize:       C.int(boolToInt(true)),
		use_symbol_type:      (1 << C.STT_FUNC) | (1 << C.STT_GNU_IFUNC),
	}))
	return C.bcc_symcache_new(C.int(pid), opt)
}

func (c *SymbolCache) Resolve(address uint64, demangle bool) *Symbol {
	symbol := new(C.struct_bcc_symbol)
	var res C.int
	if demangle {
		res = C.bcc_symcache_resolve(c.cache, C.uint64_t(address), symbol)
	} else {
		res = C.bcc_symcache_resolve_no_demangle(c.cache, C.uint64_t(address), symbol)
	}

	if res < 0 {
		module := C.GoString(symbol.module)
		if module != "" {
			return &Symbol{Offset: uint64(symbol.offset), Module: module}
		}
		return &Symbol{Offset: address}
	}

	ret := &Symbol{
		Offset: uint64(symbol.offset),
		Module: C.GoString(symbol.module),
	}
	if demangle {
		ret.Name = C.GoString(symbol.demangle_name)
		C.bcc_symbol_free_demangle_name(symbol)
	} else {
		ret.Name = C.GoString(symbol.name)
	}
	return ret
}

func (c *SymbolCache) ResolveName(module, name string) (uint64, error) {
	var address C.uint64_t
	var cmodule *C.char
	if module != "" {
		cmodule = C.CString(module)
		defer C.free(unsafe.Pointer(cmodule))
	}
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	if C.bcc_symcache_resolve_name(c.cache, cmodule, cname, &address) < 0 {
		return 0, fmt.Errorf("unable to resolve symbol %s/%s", module, name)
	}
	return uint64(address), nil
}

func (c *SymbolCache) SymbolOrAddrIfUnknown(addr uint64) string {
	sym := c.Resolve(addr, true)
	if sym == nil || sym.Module == "" {
		return formatAddress(addr)
	}
	return formatModuleName(sym.Module, sym.Offset)
}

func (c *SymbolCache) Close() {
	if c == nil || c.cache == nil {
		return
	}
	C.bcc_free_symcache(c.cache, C.int(c.pid))
}

func formatAddress(addr uint64) string {
	return fmt.Sprintf("0x%016x", addr)
}

func formatModuleName(module string, offset uint64) string {
	return fmt.Sprintf("[m] %s + 0x%08x", module, offset)
}

// resolveSymbolPath returns the file and offset to locate symname in module
func resolveSymbolPath(module string, symname string, addr uint64, pid int) (string, uint64, error) {
	if pid == -1 {
		pid = 0
	}

	modname, offset, err := bccResolveSymname(module, symname, addr, pid)
	if err != nil {
		return "", 0, fmt.Errorf("unable to locate symbol %s in module %s: %v", symname, module, err)
	}

	return modname, offset, nil
}

func bccResolveSymname(module string, symname string, addr uint64, pid int) (string, uint64, error) {
	csymbol := new(C.struct_bcc_symbol)
	cmodule := C.CString(module)
	defer C.free(unsafe.Pointer(cmodule))
	csymname := C.CString(symname)
	defer C.free(unsafe.Pointer(csymname))

	res, err := C.bcc_resolve_symname(cmodule, csymname, (C.uint64_t)(addr), C.int(pid), nil, csymbol)
	if res < 0 {
		return "", 0, fmt.Errorf("unable to locate symbol %s in module %s: %v", symname, module, err)
	}
	return C.GoString(csymbol.module), (uint64)(csymbol.offset), nil
}

func bccResolveName(module, symname string, pid int) (uint64, error) {
	csymbol := new(C.struct_bcc_symbol_option)

	pidC := C.int(pid)
	cache := C.bcc_symcache_new(pidC, csymbol)
	defer C.bcc_free_symcache(cache, pidC)

	moduleCS := C.CString(module)
	defer C.free(unsafe.Pointer(moduleCS))

	nameCS := C.CString(symname)
	defer C.free(unsafe.Pointer(nameCS))

	var addr uint64
	addrC := C.uint64_t(addr)
	res := C.bcc_symcache_resolve_name(cache, moduleCS, nameCS, &addrC)
	if res < 0 {
		return 0, fmt.Errorf("unable to locate symbol %s in module %s", symname, module)
	}

	return addr, nil
}

type symcb func(name string, addr uint64)

//export symCallback
func symCallback(name *C.char, addr C.uint64_t, _ C.uint64_t, payload unsafe.Pointer) C.int {
	handler := *(*cgo.Handle)(payload)
	if cb, ok := handler.Value().(symcb); ok && cb != nil {
		cb(C.GoString(name), uint64(addr))
	}
	return 0
}

func GetUserAddresses(module, expr string) ([]uint64, error) {
	symbols, err := MatchUserSymbols(module, expr)
	if err != nil {
		return nil, fmt.Errorf("match user symbols: %w", err)
	}
	ret := make([]uint64, len(symbols))
	for i, sym := range symbols {
		ret[i] = sym.Offset
	}
	return ret, nil
}

func GetUserFunctions(module, expr string) ([]string, error) {
	symbols, err := MatchUserSymbols(module, expr)
	if err != nil {
		return nil, fmt.Errorf("match user symbols: %w", err)
	}
	ret := make([]string, len(symbols))
	for i, sym := range symbols {
		ret[i] = sym.Name
	}
	return ret, nil
}

func MatchUserSymbols(module, expr string) ([]*Symbol, error) {
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("regexp compile: %w", err)
	}
	cname := C.CString(module)
	defer C.free(unsafe.Pointer(cname))

	var ret []*Symbol
	var cb symcb = func(name string, addr uint64) {
		if re.MatchString(name) {
			ret = append(ret, &Symbol{Name: name, Offset: addr})
		}
	}

	payload := cgo.NewHandle(cb)
	defer payload.Delete()

	opt := &C.struct_bcc_symbol_option{
		use_debug_file:       C.int(boolToInt(true)),
		check_debug_file_crc: C.int(boolToInt(true)),
		lazy_symbolize:       C.int(boolToInt(true)),
		use_symbol_type:      (1 << C.STT_FUNC) | (1 << C.STT_GNU_IFUNC),
	}

	res := C.bcc_elf_foreach_sym(cname,
		(C.bcc_elf_symcb)(unsafe.Pointer(C.symCallback)),
		unsafe.Pointer(opt),
		unsafe.Pointer(&payload),
	)

	if res < 0 {
		return nil, fmt.Errorf("error %d foreach symbols in %s", int(res), module)
	}
	return ret, nil
}
