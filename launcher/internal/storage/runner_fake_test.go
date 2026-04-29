package storage

import (
	"context"
	"fmt"
	"sync"
)

// fakeRunner matches (name, args...) prefixes to scripted responses.
// It is used by resize_test.go and poller_test.go.
type fakeRunner struct {
	mu       sync.Mutex
	script   []fakeResponse
	calls    []fakeCall
	fallback func(name string, args []string) ([]byte, error)
}

type fakeResponse struct {
	matchName string
	matchArgs []string // prefix match; nil means any
	stdout    []byte
	err       error
}

type fakeCall struct {
	name string
	args []string
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{
		fallback: func(name string, args []string) ([]byte, error) {
			return nil, fmt.Errorf("fakeRunner: unexpected call %s %v", name, args)
		},
	}
}

// Expect appends a scripted response. Calls are matched in insertion order
// against the first matching entry; unmatched calls fall through to fallback.
func (f *fakeRunner) Expect(name string, args []string, stdout []byte, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.script = append(f.script, fakeResponse{matchName: name, matchArgs: args, stdout: stdout, err: err})
}

func (f *fakeRunner) Calls() []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeCall, len(f.calls))
	copy(out, f.calls)
	return out
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, fakeCall{name: name, args: append([]string(nil), args...)})
	for i, resp := range f.script {
		if resp.matchName != name {
			continue
		}
		if !argsPrefixMatch(resp.matchArgs, args) {
			continue
		}
		f.script = append(f.script[:i], f.script[i+1:]...)
		f.mu.Unlock()
		return resp.stdout, resp.err
	}
	f.mu.Unlock()
	return f.fallback(name, args)
}

func argsPrefixMatch(want, got []string) bool {
	if want == nil {
		return true
	}
	if len(got) < len(want) {
		return false
	}
	for i, w := range want {
		if got[i] != w {
			return false
		}
	}
	return true
}
