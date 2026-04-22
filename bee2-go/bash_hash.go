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

// NewBashHash returns a hash.Hash computing the bash hash.
// l parameter must be 128, 192, or 256.
func NewBashHash(l int) (hash.Hash, error) {
	if l != 128 && l != 192 && l != 256 {
		return nil, errors.New("invalid l parameter: must be 128, 192, or 256")
	}

	stateSize := int(C.bashHash_keep())
	state := C.malloc(C.size_t(stateSize))
	if state == nil {
		return nil, errors.New("failed to allocate memory for bashHash state")
	}

	C.bashHashStart(state, C.size_t(l))

	return &bashHash{
		state: state,
		l:     l,
	}, nil
}

func (h *bashHash) Write(p []byte) (n int, err error) {
	if len(p) > 0 {
		C.bashHashStepH(unsafe.Pointer(&p[0]), C.size_t(len(p)), h.state)
	}
	return len(p), nil
}

func (h *bashHash) Sum(b []byte) []byte {
	hashLen := h.l / 4
	out := make([]byte, hashLen)
	
	// According to documentation, StepG does not allow continuation if buffer intersects.
	// We can use a temporary copy of the state to allow Sum() to be called multiple times.
	stateSize := int(C.bashHash_keep())
	tempState := C.malloc(C.size_t(stateSize))
	if tempState == nil {
		panic("failed to allocate memory for temporary bashHash state")
	}
	defer C.free(tempState)

	C.memcpy(tempState, h.state, C.size_t(stateSize))
	
	C.bashHashStepG((*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(hashLen), tempState)
	
	return append(b, out...)
}

func (h *bashHash) Reset() {
	C.bashHashStart(h.state, C.size_t(h.l))
}

func (h *bashHash) Size() int {
	return h.l / 4
}

func (h *bashHash) BlockSize() int {
	// 24 for l=128, 48 for l=256 etc, typical for sponge, but let's return a safe value
	// actually standard says capacity is 2l, bit rate is 1536 - 2l
	return (1536 - 2*h.l) / 8
}

// Free should be called to free the underlying C memory
func (h *bashHash) Free() {
	if h.state != nil {
		C.free(h.state)
		h.state = nil
	}
}

// BashHash is a helper wrapper for one-shot hashing.
func BashHash(l int, src []byte) ([]byte, error) {
	h, err := NewBashHash(l)
	if err != nil {
		return nil, err
	}
	defer h.(*bashHash).Free()
	h.Write(src)
	return h.Sum(nil), nil
}
