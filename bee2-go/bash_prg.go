package bee2go

/*
#cgo CFLAGS: -I${SRCDIR}/../bee2/include
#cgo LDFLAGS: -L${SRCDIR}/../bee2/build/src -lbee2_static
#include <stdlib.h>
#include "bee2/crypto/bash.h"
*/
import "C"
import (
	"errors"
	"unsafe"
)

type BashPrg struct {
	state unsafe.Pointer
	l     int
}

func NewBashPrg(l int, d int, ann []byte, key []byte) (*BashPrg, error) {
	if l != 128 && l != 192 && l != 256 {
		return nil, errors.New("invalid l parameter: must be 128, 192, or 256")
	}
	if d != 1 && d != 2 {
		return nil, errors.New("invalid d parameter: must be 1 or 2")
	}

	stateSize := int(C.bashPrg_keep())
	state := C.malloc(C.size_t(stateSize))
	if state == nil {
		return nil, errors.New("failed to allocate memory for bashPrg state")
	}

	var annPtr *C.uint8_t
	if len(ann) > 0 {
		annPtr = (*C.uint8_t)(unsafe.Pointer(&ann[0]))
	}

	var keyPtr *C.uint8_t
	if len(key) > 0 {
		keyPtr = (*C.uint8_t)(unsafe.Pointer(&key[0]))
	}

	C.bashPrgStart(
		state,
		C.size_t(l),
		C.size_t(d),
		annPtr,
		C.size_t(len(ann)),
		keyPtr,
		C.size_t(len(key)),
	)

	return &BashPrg{
		state: state,
		l:     l,
	}, nil
}

func (p *BashPrg) Free() {
	if p.state != nil {
		C.free(p.state)
		p.state = nil
	}
}

func (p *BashPrg) Absorb(buf []byte) {
	if p.state == nil || len(buf) == 0 {
		return
	}
	C.bashPrgAbsorb(
		unsafe.Pointer(&buf[0]),
		C.size_t(len(buf)),
		p.state,
	)
}

func (p *BashPrg) Squeeze(count int) []byte {
	if p.state == nil || count <= 0 {
		return nil
	}
	
	out := make([]byte, count)
	C.bashPrgSqueeze(
		unsafe.Pointer(&out[0]),
		C.size_t(count),
		p.state,
	)
	return out
}
