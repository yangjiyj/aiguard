package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const seenTTL = 24 * time.Hour

// seenStore 记录已处理的任务 id（state/seen.log，每行 "unix_ts id"），防重放。
type seenStore struct {
	mu   sync.Mutex
	path string
	m    map[string]time.Time
}

func loadSeen(path string, now time.Time) (*seenStore, error) {
	s := &seenStore{path: path, m: map[string]time.Time{}}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	defer f.Close()
	dropped := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) != 2 {
			continue
		}
		ts, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			continue
		}
		t := time.Unix(ts, 0)
		if now.Sub(t) > seenTTL {
			dropped = true
			continue
		}
		s.m[parts[1]] = t
	}
	if dropped {
		_ = s.rewriteLocked()
	}
	return s, nil
}

func (s *seenStore) has(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.m[id]
	return ok
}

// add 先落盘再返回；落盘失败视为错误（调用方应拒绝执行，宁可不执行也不留重放窗口）。
func (s *seenStore) add(id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "%d %s\n", now.Unix(), id); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	s.m[id] = now
	return nil
}

// prune 清理过期记录并在有变化时重写文件。
func (s *seenStore) prune(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for id, t := range s.m {
		if now.Sub(t) > seenTTL {
			delete(s.m, id)
			changed = true
		}
	}
	if changed {
		_ = s.rewriteLocked()
	}
}

func (s *seenStore) rewriteLocked() error {
	var b strings.Builder
	for id, t := range s.m {
		fmt.Fprintf(&b, "%d %s\n", t.Unix(), id)
	}
	return atomicWrite(s.path, []byte(b.String()), 0o600)
}

// atomicWrite 先写同目录临时文件，再 rename。
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() { _ = os.Remove(name) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(name, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
