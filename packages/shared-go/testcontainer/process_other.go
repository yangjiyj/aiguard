//go:build !unix

package testcontainer

// processAlive 在判断不了进程存活的平台上一律当作活着：宁可不回收，也不误删别人的容器。
func processAlive(pid int) bool { return pid > 0 }
