package cpuonline

import (
	"os"

	"github.com/vietanhduong/go-bpf/pkg/cpurange"
)

const cpuOnline = "/sys/devices/system/cpu/online"

// Get returns a slice with the online CPUs, for example `[0, 2, 3]`
func Get() ([]uint, error) {
	buf, err := os.ReadFile(cpuOnline)
	if err != nil {
		return nil, err
	}
	return cpurange.ReadCPURange(string(buf))
}
