package bcc

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
)

const KernelAddressSpace = 0x00ffffffffffffff

type Symbol struct {
	Name    string
	Module  string
	Address uint64
}

func (k *Symbol) String() string {
	if k == nil {
		return ""
	}
	return fmt.Sprintf("module=%s symbol=%s address=0x%016x", k.Module, k.Name, k.Address)
}

func LoadProcKallsym() ([]*Symbol, error) {
	var ret []*Symbol
	LoadProcKallsymWithCallback(func(sym *Symbol) { ret = append(ret, sym) })
	return ret, nil
}

func LoadProcKallsymWithCallback(callback func(sym *Symbol)) error {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return fmt.Errorf("open /proc/kallsyms: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 3 { // This should never happen
			continue
		}
		sym := &Symbol{Name: parts[2], Module: "kernel"}

		if parts[1][0] == 'b' || parts[1][0] == 'B' ||
			parts[1][0] == 'd' || parts[1][0] == 'D' ||
			parts[1][0] == 'r' || parts[1][0] == 'R' {
			continue
		}

		sym.Address, _ = strconv.ParseUint(parts[0], 16, 0)
		if sym.Address == 0 || sym.Address == math.MaxUint64 || sym.Address < KernelAddressSpace {
			continue
		}

		parts = append(parts, "")
		if len(parts[3]) > 0 && parts[3][0] == '[' && parts[3][len(parts[3])-1] == ']' {
			sym.Module = parts[3][1 : len(parts[3])-1]
		}

		callback(sym)
	}

	if err = scanner.Err(); err != nil {
		return fmt.Errorf("scanner error: %w", err)
	}
	return nil
}
