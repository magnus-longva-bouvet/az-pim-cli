//go:build unix

package readiness

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// lockFile takes the lock msal_extensions takes before it touches az's token
// cache: flock on "<cache>.lockfile". msal_extensions deletes that file when it
// lets go, so a lock taken on the old file guards nothing; the path is checked
// to still name the locked file, and the lock is taken again otherwise.
func lockFile(path string) (func(), error) {
	deadline := time.Now().Add(10 * time.Second)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, err
		}
		if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil && namesFile(path, f) {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		_ = f.Close()
		if time.Now().After(deadline) {
			return nil, errors.New("another process kept az's token cache locked")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func namesFile(path string, f *os.File) bool {
	opened, err := f.Stat()
	if err != nil {
		return false
	}
	current, err := os.Stat(path)
	return err == nil && os.SameFile(opened, current)
}
