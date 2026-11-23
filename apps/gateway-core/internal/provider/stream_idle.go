package provider

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

var ErrUpstreamStreamIdleTimeout = errors.New("upstream stream byte-idle timeout")

type byteIdleReadCloser struct {
	body      io.ReadCloser
	timeout   time.Duration
	cancel    context.CancelFunc
	closeOnce sync.Once
	timedOut  atomic.Bool
	mu        sync.Mutex
	timer     *time.Timer
	closeErr  error
}

func newByteIdleReadCloser(body io.ReadCloser, timeout time.Duration, cancel context.CancelFunc) io.ReadCloser {
	return &byteIdleReadCloser{body: body, timeout: timeout, cancel: cancel}
}

func (r *byteIdleReadCloser) Read(p []byte) (int, error) {
	if r.timeout <= 0 {
		n, err := r.body.Read(p)
		if r.timedOut.Load() {
			return n, ErrUpstreamStreamIdleTimeout
		}
		return n, err
	}
	timer := time.AfterFunc(r.timeout, r.timeoutClose)
	r.mu.Lock()
	r.timer = timer
	r.mu.Unlock()
	n, err := r.body.Read(p)
	timer.Stop()
	r.mu.Lock()
	if r.timer == timer {
		r.timer = nil
	}
	r.mu.Unlock()
	if r.timedOut.Load() {
		return n, ErrUpstreamStreamIdleTimeout
	}
	return n, err
}

func (r *byteIdleReadCloser) timeoutClose() {
	r.closeOnce.Do(func() {
		r.timedOut.Store(true)
		if r.cancel != nil {
			r.cancel()
		}
		r.closeErr = r.body.Close()
	})
}

func (r *byteIdleReadCloser) Close() error {
	r.mu.Lock()
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
	r.mu.Unlock()
	r.closeOnce.Do(func() {
		if r.cancel != nil {
			r.cancel()
		}
		r.closeErr = r.body.Close()
	})
	return r.closeErr
}
