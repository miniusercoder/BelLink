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

// BashPrg wraps the bash programmable automaton (СТБ 34.101.77, bashPrg).
// In keyed mode (key != nil) it provides AEAD-style stream cipher and MAC:
//
//	NewBashPrg(l, d, ann, key) → Absorb(aad) → Encrypt(data) → Squeeze(tagLen)
type BashPrg struct {
	state unsafe.Pointer
	l     int
}

// NewBashPrg initialises the bash automaton.
//
// l must be 128, 192, or 256 (security level in bits).
// d must be 1 or 2 (capacity multiplier).
// ann is the optional announcement (len must be a multiple of 4, ≤ 60 bytes).
// key is the optional key; if non-nil the automaton enters keyed mode
// (len must be a multiple of 4, between l/8 and 60 bytes).
func NewBashPrg(l, d int, ann, key []byte) (*BashPrg, error) {
	if l != 128 && l != 192 && l != 256 {
		return nil, errors.New("bee2: security level l must be 128, 192, or 256")
	}
	if d != 1 && d != 2 {
		return nil, errors.New("bee2: capacity d must be 1 or 2")
	}

	state := C.malloc(C.size_t(C.bashPrg_keep()))
	if state == nil {
		return nil, errors.New("bee2: failed to allocate bashPrg state")
	}

	var annPtr *C.octet
	if len(ann) > 0 {
		annPtr = (*C.octet)(unsafe.Pointer(&ann[0]))
	}
	var keyPtr *C.octet
	if len(key) > 0 {
		keyPtr = (*C.octet)(unsafe.Pointer(&key[0]))
	}

	C.bashPrgStart(
		state,
		C.size_t(l),
		C.size_t(d),
		annPtr, C.size_t(len(ann)),
		keyPtr, C.size_t(len(key)),
	)
	return &BashPrg{state: state, l: l}, nil
}

// Restart re-initialises the automaton with a new announcement and key,
// reusing the security level and capacity from the original NewBashPrg call.
func (p *BashPrg) Restart(ann, key []byte) {
	var annPtr *C.octet
	if len(ann) > 0 {
		annPtr = (*C.octet)(unsafe.Pointer(&ann[0]))
	}
	var keyPtr *C.octet
	if len(key) > 0 {
		keyPtr = (*C.octet)(unsafe.Pointer(&key[0]))
	}
	// bashPrgRestart signature: (ann, ann_len, key, key_len, state)
	C.bashPrgRestart(annPtr, C.size_t(len(ann)), keyPtr, C.size_t(len(key)), p.state)
}

// Absorb loads buf into the automaton (e.g. additional authenticated data).
func (p *BashPrg) Absorb(buf []byte) {
	if len(buf) == 0 {
		return
	}
	C.bashPrgAbsorb(unsafe.Pointer(&buf[0]), C.size_t(len(buf)), p.state)
}

// Squeeze outputs count pseudo-random bytes from the automaton.
func (p *BashPrg) Squeeze(count int) []byte {
	if count <= 0 {
		return nil
	}
	out := make([]byte, count)
	C.bashPrgSqueeze(unsafe.Pointer(&out[0]), C.size_t(count), p.state)
	return out
}

// Encrypt encrypts buf in-place using the automaton (keyed mode required).
// The slice is modified directly; no copy is made.
func (p *BashPrg) Encrypt(buf []byte) {
	if len(buf) == 0 {
		return
	}
	C.bashPrgEncr(unsafe.Pointer(&buf[0]), C.size_t(len(buf)), p.state)
}

// Decrypt decrypts buf in-place using the automaton (keyed mode required).
// The slice is modified directly; no copy is made.
func (p *BashPrg) Decrypt(buf []byte) {
	if len(buf) == 0 {
		return
	}
	C.bashPrgDecr(unsafe.Pointer(&buf[0]), C.size_t(len(buf)), p.state)
}

// Ratchet irreversibly advances the automaton state so that past output
// cannot be recovered from the new state.
func (p *BashPrg) Ratchet() {
	C.bashPrgRatchet(p.state)
}

// Free releases the underlying C state. Must be called when the PRG is no longer needed.
func (p *BashPrg) Free() {
	if p.state != nil {
		C.free(p.state)
		p.state = nil
	}
}
