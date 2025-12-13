package output

import (
	"io"
	"os"
	"sync"
)

// syncWriter wraps an io.Writer with a mutex to ensure atomic writes
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (sw *syncWriter) Write(p []byte) (n int, err error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.w.Write(p)
}

// Stdout is a synchronized writer that prevents interleaved output
// from concurrent goroutines and subprocesses
var Stdout io.Writer = &syncWriter{w: os.Stdout}
