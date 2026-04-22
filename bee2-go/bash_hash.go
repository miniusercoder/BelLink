package bee2go

/*
#cgo CFLAGS: -I${SRCDIR}/../bee2/include
#cgo LDFLAGS: -L${SRCDIR}/../bee2/build/src -lbee2_static
#include <stdlib.h>
#include <string.h>
#include "bee2/crypto/bash.h"
*/
import "C"
import (
	"errors"
	"hash"
	"unsafe"
)

type bashHash struct {
	state unsafe.Pointer
	l     int
}

// NewBashHash returns a hash.Hash computing bash hash at security level l.
// l must be 128, 192, or 256; the digest size is l/4 bytes (e.g. 32 bytes for l=128).
func NewBashHash(l int) (hash.Hash, error) {
	if l != 128 && l != 192 && l != 256 {
		return nil, errors.New("bee2: security level l must be 128, 192, or 256")
	}
	state := C.malloc(C.size_t(C.bashHash_keep()))
	if state == nil {
		return nil, errors.New("bee2: failed to allocate bashHash state")
	}
	C.bashHashStart(state, C.size_t(l))
	return &bashHash{state: state, l: l}, nil
}

func (h *bashHash) Write(p []byte) (int, error) {
	if len(p) > 0 {
		C.bashHashStepH(unsafe.Pointer(&p[0]), C.size_t(len(p)), h.state)
	}
	return len(p), nil
}

func (h *bashHash) Sum(b []byte) []byte {
	hashLen := h.l / 4
	out := make([]byte, hashLen)

	// Copy state so Sum can be called multiple times without consuming it.
	stateSize := C.size_t(C.bashHash_keep())
	tmp := C.malloc(stateSize)
	if tmp == nil {
		panic("bee2: failed to allocate temporary bashHash state")
	}
	defer C.free(tmp)
	C.memcpy(tmp, h.state, stateSize)

	C.bashHashStepG((*C.octet)(unsafe.Pointer(&out[0])), C.size_t(hashLen), tmp)
	return append(b, out...)
}

func (h *bashHash) Reset() {
	C.bashHashStart(h.state, C.size_t(h.l))
}

// Size returns the digest size in bytes (l/4).
func (h *bashHash) Size() int {
	return h.l / 4
}

// BlockSize returns the sponge rate in bytes ((1536 - 2*l) / 8).
func (h *bashHash) BlockSize() int {
	return (1536 - 2*h.l) / 8
}

// Free releases the underlying C state. Must be called when the hash is no longer needed.
func (h *bashHash) Free() {
	if h.state != nil {
		C.free(h.state)
		h.state = nil
	}
}

// BashHash computes the bash hash of src at security level l in a single call.
// l must be 128, 192, or 256.
func BashHash(l int, src []byte) ([]byte, error) {
	h, err := NewBashHash(l)
	if err != nil {
		return nil, err
	}
	defer h.(*bashHash).Free()
	if _, err := h.Write(src); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
