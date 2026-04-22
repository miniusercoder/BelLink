package bee2go

/*
#cgo CFLAGS: -I${SRCDIR}/../bee2/include
#cgo LDFLAGS: -L${SRCDIR}/../bee2/build/src -lbee2_static
#include <stdlib.h>
#include "bee2/crypto/bake.h"
#include "bee2/crypto/bign.h"

// typedefs and wrappers to avoid cgo issues with function pointers
typedef err_t (*bake_certval_func)(octet*, const bign_params*, const octet*, size_t);

static err_t call_bake_certval(bake_certval_func fn, octet pubkey[], const bign_params* params, const octet* data, size_t len) {
    return fn(pubkey, params, data, len);
}
*/
import "C"
import (
	"errors"
	"unsafe"
)

type BakeSettings struct {
	settings *C.bake_settings
}

func NewBakeSettings(kca bool, kcb bool, helloa []byte, hellob []byte) (*BakeSettings, error) {
	settings := (*C.bake_settings)(C.malloc(C.size_t(unsafe.Sizeof(C.bake_settings{}))))
	if settings == nil {
		return nil, errors.New("failed to allocate memory for bake_settings")
	}

	settings.kca = C.bool_t(0)
	if kca {
		settings.kca = C.bool_t(1)
	}

	settings.kcb = C.bool_t(0)
	if kcb {
		settings.kcb = C.bool_t(1)
	}

	if len(helloa) > 0 {
		settings.helloa = unsafe.Pointer(&helloa[0])
		settings.helloa_len = C.size_t(len(helloa))
	} else {
		settings.helloa = nil
		settings.helloa_len = 0
	}

	if len(hellob) > 0 {
		settings.hellob = unsafe.Pointer(&hellob[0])
		settings.hellob_len = C.size_t(len(hellob))
	} else {
		settings.hellob = nil
		settings.hellob_len = 0
	}
	
	// Rng should be set from C code if needed or passed properly. Here we set it to zero.
	settings.rng = nil
	settings.rng_state = nil

	return &BakeSettings{settings: settings}, nil
}

func (s *BakeSettings) Free() {
	if s.settings != nil {
		C.free(unsafe.Pointer(s.settings))
		s.settings = nil
	}
}

type BignParams struct {
	params *C.bign_params
}

func NewBignParamsStd(name string) (*BignParams, error) {
	params := (*C.bign_params)(C.malloc(C.size_t(unsafe.Sizeof(C.bign_params{}))))
	if params == nil {
		return nil, errors.New("failed to allocate memory for bign_params")
	}

	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	err := C.bignParamsStd(params, cName)
	if err != 0 {
		C.free(unsafe.Pointer(params))
		return nil, errors.New("bignParamsStd failed")
	}

	return &BignParams{params: params}, nil
}

func (p *BignParams) Free() {
	if p.params != nil {
		C.free(unsafe.Pointer(p.params))
		p.params = nil
	}
}

type BakeCert struct {
	cert *C.bake_cert
}

// Note: BakeCert creation might need specific logic depending on how validation function is passed.
// For now, we leave it as unsafe.Pointer to allow passing from C side.
func NewBakeCertFromC(certPtr unsafe.Pointer) *BakeCert {
	return &BakeCert{cert: (*C.bake_cert)(certPtr)}
}


type BakeBSTS struct {
	state unsafe.Pointer
	l     int
}

func NewBakeBSTS(l int, params *BignParams, settings *BakeSettings, privKey []byte, cert *BakeCert) (*BakeBSTS, error) {
	if params == nil || settings == nil || cert == nil {
		return nil, errors.New("params, settings, and cert cannot be nil")
	}

	stateSize := int(C.bakeBSTS_keep(C.size_t(l)))
	state := C.malloc(C.size_t(stateSize))
	if state == nil {
		return nil, errors.New("failed to allocate memory for bakeBSTS state")
	}

	var privKeyPtr *C.uint8_t
	if len(privKey) > 0 {
		privKeyPtr = (*C.uint8_t)(unsafe.Pointer(&privKey[0]))
	}

	err := C.bakeBSTSStart(
		state,
		params.params,
		settings.settings,
		privKeyPtr,
		cert.cert,
	)

	if err != 0 {
		C.free(state)
		return nil, errors.New("bakeBSTSStart failed")
	}

	return &BakeBSTS{
		state: state,
		l:     l,
	}, nil
}

func (b *BakeBSTS) Free() {
	if b.state != nil {
		C.free(b.state)
		b.state = nil
	}
}

func (b *BakeBSTS) Step2() ([]byte, error) {
	out := make([]byte, b.l/2)
	err := C.bakeBSTSStep2((*C.uint8_t)(unsafe.Pointer(&out[0])), b.state)
	if err != 0 {
		return nil, errors.New("bakeBSTSStep2 failed")
	}
	return out, nil
}

func (b *BakeBSTS) Step3(in []byte, certLen int) ([]byte, error) {
	// M2 = [3 * l / 4 + cert->len + 8]out
	out := make([]byte, (3*b.l)/4+certLen+8)
	
	var inPtr *C.uint8_t
	if len(in) > 0 {
		inPtr = (*C.uint8_t)(unsafe.Pointer(&in[0]))
	}
	
	err := C.bakeBSTSStep3(
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		inPtr,
		b.state,
	)
	if err != 0 {
		return nil, errors.New("bakeBSTSStep3 failed")
	}
	return out, nil
}

func (b *BakeBSTS) Step4(in []byte, certLen int, vala unsafe.Pointer) ([]byte, error) {
	// M3 = [l / 4 + cert->len + 8]out
	out := make([]byte, b.l/4+certLen+8)

	var inPtr *C.uint8_t
	if len(in) > 0 {
		inPtr = (*C.uint8_t)(unsafe.Pointer(&in[0]))
	}

	err := C.bakeBSTSStep4(
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		inPtr,
		C.size_t(len(in)),
		(C.bake_certval_i)(vala),
		b.state,
	)
	if err != 0 {
		return nil, errors.New("bakeBSTSStep4 failed")
	}
	return out, nil
}

func (b *BakeBSTS) Step5(in []byte, valb unsafe.Pointer) error {
	var inPtr *C.uint8_t
	if len(in) > 0 {
		inPtr = (*C.uint8_t)(unsafe.Pointer(&in[0]))
	}

	err := C.bakeBSTSStep5(
		inPtr,
		C.size_t(len(in)),
		(C.bake_certval_i)(valb),
		b.state,
	)
	if err != 0 {
		return errors.New("bakeBSTSStep5 failed")
	}
	return nil
}

func (b *BakeBSTS) StepG() ([]byte, error) {
	key := make([]byte, 32)
	err := C.bakeBSTSStepG((*C.uint8_t)(unsafe.Pointer(&key[0])), b.state)
	if err != 0 {
		return nil, errors.New("bakeBSTSStepG failed")
	}
	return key, nil
}
