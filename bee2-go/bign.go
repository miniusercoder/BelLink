package bee2go

/*
#cgo CFLAGS: -I${SRCDIR}/../bee2/include
#cgo LDFLAGS: -L${SRCDIR}/../bee2/build/src -lbee2_static
#include <stdlib.h>
#include <stdio.h>
#include "bee2/crypto/bign.h"

// urandom_gen is a gen_i implementation that reads from /dev/urandom.
// CGO cannot convert a Go function to a C function pointer, so this
// C-side wrapper is used instead. Not declared static so the linker
// can resolve the symbol reference emitted by CGO.
void urandom_gen(void* buf, size_t count, void* state) {
	FILE* f = fopen("/dev/urandom", "rb");
	if (f) {
		fread(buf, 1, count, f);
		fclose(f);
	}
}
*/
import "C"
import (
	"errors"
	"unsafe"
)

const (
	// bignCurve256v1 is the OID for bign-curve256v1 (l=128, private key 32 B, public key 64 B).
	bignCurve256v1 = "1.2.112.0.2.0.34.101.45.3.1"
)

// BignKeypairGen generates a random bign keypair using the given params.
// It returns (privKey [l/4]byte, pubKey [l/2]byte).
// For bign-curve256v1 (l=128): privKey is 32 bytes, pubKey is 64 bytes.
func BignKeypairGen(params *BignParams) (privKey, pubKey []byte, err error) {
	if params == nil {
		return nil, nil, errors.New("bee2: params must not be nil")
	}
	l := int(params.params.l)
	privLen := l / 4
	pubLen := l / 2

	privKey = make([]byte, privLen)
	pubKey = make([]byte, pubLen)

	rc := C.bignKeypairGen(
		(*C.octet)(unsafe.Pointer(&privKey[0])),
		(*C.octet)(unsafe.Pointer(&pubKey[0])),
		params.params,
		(C.gen_i)(C.urandom_gen),
		nil,
	)
	if rc != 0 {
		return nil, nil, errors.New("bee2: bignKeypairGen failed")
	}
	return privKey, pubKey, nil
}

// BignPubkeyCalc derives the public key from privKey using params.
// For bign-curve256v1: privKey must be 32 bytes, returns 64-byte public key.
func BignPubkeyCalc(params *BignParams, privKey []byte) ([]byte, error) {
	if params == nil {
		return nil, errors.New("bee2: params must not be nil")
	}
	l := int(params.params.l)
	pubKey := make([]byte, l/2)

	rc := C.bignPubkeyCalc(
		(*C.octet)(unsafe.Pointer(&pubKey[0])),
		params.params,
		(*C.octet)(unsafe.Pointer(&privKey[0])),
	)
	if rc != 0 {
		return nil, errors.New("bee2: bignPubkeyCalc failed")
	}
	return pubKey, nil
}

// BignDH computes the Diffie-Hellman shared secret: privKey * peerPubKey → keyLen bytes.
// keyLen must be ≤ l/2 (e.g. ≤ 64 for bign-curve256v1).
func BignDH(params *BignParams, privKey, peerPubKey []byte, keyLen int) ([]byte, error) {
	if params == nil {
		return nil, errors.New("bee2: params must not be nil")
	}
	sharedKey := make([]byte, keyLen)

	rc := C.bignDH(
		(*C.octet)(unsafe.Pointer(&sharedKey[0])),
		params.params,
		(*C.octet)(unsafe.Pointer(&privKey[0])),
		(*C.octet)(unsafe.Pointer(&peerPubKey[0])),
		C.size_t(keyLen),
	)
	if rc != 0 {
		return nil, errors.New("bee2: bignDH failed")
	}
	return sharedKey, nil
}

// NewBignParams256v1 is a convenience wrapper that loads bign-curve256v1 parameters.
func NewBignParams256v1() (*BignParams, error) {
	return NewBignParamsStd(bignCurve256v1)
}
