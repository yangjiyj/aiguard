//go:build unix

package testcontainer

import (
	"errors"
	"syscall"
)

// processAlive 报告 pid 对应的进程是否还在：发 0 号信号，进程存在（含无权发信号的别人的进程）都算活着。
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
