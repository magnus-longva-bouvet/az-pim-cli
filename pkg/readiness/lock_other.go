//go:build !unix

package readiness

import "errors"

// lockFile is not implemented off Unix. On Windows az's token cache is
// encrypted with DPAPI or held by the WAM broker, so a file lock would not be
// enough to edit it anyway.
func lockFile(string) (func(), error) {
	return nil, errors.ErrUnsupported
}
