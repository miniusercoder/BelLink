package bee2go

/*
#cgo CFLAGS: -I${SRCDIR}/../bee2/include
#cgo LDFLAGS: -L${SRCDIR}/../bee2/build/src -lbee2_static
#include <stdlib.h>
#include <string.h>
#include "bee2/crypto/bake.h"
#include "bee2/crypto/bign.h"

// CGO cannot cast unsafe.Pointer to a C function-pointer type directly.
// These thin wrappers accept void* and perform the cast in C, where it is valid.

static void bake_settings_set_rng(bake_settings* s, void* rng_fn, void* rng_state) {
	s->rng = (gen_i)rng_fn;
	s->rng_state = rng_state;
}

static bake_cert* make_bake_cert(octet* data, size_t len, void* val_fn) {
	bake_cert* c = (bake_cert*)malloc(sizeof(bake_cert));
	if (c) {
		c->data = data;
		c->len  = len;
		c->val  = (bake_certval_i)val_fn;
	}
	return c;
}

static err_t bsts_step4_wrap(
	octet* out, const octet* in, size_t in_len, void* vala, void* state)
{
	return bakeBSTSStep4(out, in, in_len, (bake_certval_i)vala, state);
}

static err_t bsts_step5_wrap(
	const octet* in, size_t in_len, void* valb, void* state)
{
	return bakeBSTSStep5(in, in_len, (bake_certval_i)valb, state);
}
*/
import "C"
import (
	"errors"
	"unsafe"
)

// ────────────────────────────────────────────────────────────────────────────
// BignParams
// ────────────────────────────────────────────────────────────────────────────

// BignParams wraps the bign long-term parameters (bign_params).
type BignParams struct {
	params *C.bign_params
}

// NewBignParamsStd loads a standard bign parameter set by name.
// Valid names include "1.2.112.0.2.0.34.101.45.3.1" (bign-curve256v1), etc.
func NewBignParamsStd(name string) (*BignParams, error) {
	params := (*C.bign_params)(C.malloc(C.size_t(C.sizeof_bign_params)))
	if params == nil {
		return nil, errors.New("bee2: failed to allocate bign_params")
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	if rc := C.bignParamsStd(params, cName); rc != 0 {
		C.free(unsafe.Pointer(params))
		return nil, errors.New("bee2: bignParamsStd failed")
	}
	return &BignParams{params: params}, nil
}

// Free releases the underlying C memory.
func (p *BignParams) Free() {
	if p.params != nil {
		C.free(unsafe.Pointer(p.params))
		p.params = nil
	}
}

// ────────────────────────────────────────────────────────────────────────────
// BakeSettings
// ────────────────────────────────────────────────────────────────────────────

// BakeSettings wraps bake_settings.
// rng and rngState must be C-side values; rng is a gen_i function pointer
// passed as unsafe.Pointer to avoid CGO function-pointer restrictions.
type BakeSettings struct {
	settings *C.bake_settings
	helloa   unsafe.Pointer // C copy of party-A hello message
	hellob   unsafe.Pointer // C copy of party-B hello message
}

// NewBakeSettings allocates and populates a bake_settings struct.
//
// rng must be a C gen_i function pointer (cast to unsafe.Pointer by the caller).
// rngState is the opaque state passed back to rng on each call.
// helloa / hellob are optional greeting messages; pass nil to omit.
func NewBakeSettings(kca, kcb bool, helloa, hellob []byte, rng, rngState unsafe.Pointer) (*BakeSettings, error) {
	s := (*C.bake_settings)(C.calloc(1, C.size_t(C.sizeof_bake_settings)))
	if s == nil {
		return nil, errors.New("bee2: failed to allocate bake_settings")
	}
	bs := &BakeSettings{settings: s}

	if kca {
		s.kca = 1
	}
	if kcb {
		s.kcb = 1
	}

	if len(helloa) > 0 {
		bs.helloa = C.CBytes(helloa)
		s.helloa = bs.helloa
		s.helloa_len = C.size_t(len(helloa))
	}
	if len(hellob) > 0 {
		bs.hellob = C.CBytes(hellob)
		s.hellob = bs.hellob
		s.hellob_len = C.size_t(len(hellob))
	}

	if rng != nil {
		C.bake_settings_set_rng(s, rng, rngState)
	}
	return bs, nil
}

// Free releases C memory owned by BakeSettings.
func (s *BakeSettings) Free() {
	if s.helloa != nil {
		C.free(s.helloa)
		s.helloa = nil
	}
	if s.hellob != nil {
		C.free(s.hellob)
		s.hellob = nil
	}
	if s.settings != nil {
		C.free(unsafe.Pointer(s.settings))
		s.settings = nil
	}
}

// ────────────────────────────────────────────────────────────────────────────
// BakeCert
// ────────────────────────────────────────────────────────────────────────────

// BakeCert wraps bake_cert.
type BakeCert struct {
	cert  *C.bake_cert
	data  unsafe.Pointer // C-allocated copy of cert data (nil when not owned)
	owned bool
}

// NewBakeCert creates a BakeCert from raw DER/binary cert data and a C-side
// validation function pointer (bake_certval_i cast to unsafe.Pointer).
// Pass nil for valFn to skip validation (not recommended for production).
func NewBakeCert(data []byte, valFn unsafe.Pointer) (*BakeCert, error) {
	cData := C.CBytes(data)
	cert := C.make_bake_cert((*C.octet)(cData), C.size_t(len(data)), valFn)
	if cert == nil {
		C.free(cData)
		return nil, errors.New("bee2: failed to allocate bake_cert")
	}
	return &BakeCert{cert: cert, data: cData, owned: true}, nil
}

// NewBakeCertFromC wraps a bake_cert that is already fully configured on the
// C side. The caller is responsible for the lifetime of the underlying memory.
func NewBakeCertFromC(certPtr unsafe.Pointer) *BakeCert {
	return &BakeCert{cert: (*C.bake_cert)(certPtr), owned: false}
}

// Free releases C memory owned by this BakeCert.
func (c *BakeCert) Free() {
	if !c.owned {
		return
	}
	if c.data != nil {
		C.free(c.data)
		c.data = nil
	}
	if c.cert != nil {
		C.free(unsafe.Pointer(c.cert))
		c.cert = nil
	}
}

// ────────────────────────────────────────────────────────────────────────────
// BakeBSTS
// ────────────────────────────────────────────────────────────────────────────

// BakeBSTS wraps the BSTS protocol state (СТБ 34.101.66).
//
// Protocol flow (party A initiates):
//
//	B: state = NewBakeBSTS(...)   A: state = NewBakeBSTS(...)
//	B: m1, _ = state.Step2()     → send m1 →
//	                              A: m2, _ = state.Step3(m1)
//	                              ← send m2 ←
//	B: m3, _ = state.Step4(m2, vala)   → send m3 →
//	                              A: state.Step5(m3, valb)
//	B: key, _ = state.StepG()    A: key, _ = state.StepG()
type BakeBSTS struct {
	state   unsafe.Pointer
	l       int // security level (bits): 128, 192, or 256
	certLen int // own certificate length (bytes), used to size output buffers
}

// NewBakeBSTS initialises BSTS for one party.
//
// l is the security level in bits (e.g. 128 for bign-curve256v1).
// privKey must be l/4 bytes long (32 bytes for l=128).
func NewBakeBSTS(l int, params *BignParams, settings *BakeSettings, privKey []byte, cert *BakeCert) (*BakeBSTS, error) {
	if params == nil || settings == nil || cert == nil {
		return nil, errors.New("bee2: params, settings, and cert must not be nil")
	}

	state := C.malloc(C.size_t(C.bakeBSTS_keep(C.size_t(l))))
	if state == nil {
		return nil, errors.New("bee2: failed to allocate bakeBSTS state")
	}

	var privKeyPtr *C.octet
	if len(privKey) > 0 {
		privKeyPtr = (*C.octet)(unsafe.Pointer(&privKey[0]))
	}

	rc := C.bakeBSTSStart(state, params.params, settings.settings, privKeyPtr, cert.cert)
	if rc != 0 {
		C.free(state)
		return nil, errors.New("bee2: bakeBSTSStart failed")
	}

	return &BakeBSTS{
		state:   state,
		l:       l,
		certLen: int(cert.cert.len),
	}, nil
}

// Free releases the underlying C state.
func (b *BakeBSTS) Free() {
	if b.state != nil {
		C.free(b.state)
		b.state = nil
	}
}

// Step2 is called by party B to produce message M1 (size: l/2 bytes).
func (b *BakeBSTS) Step2() ([]byte, error) {
	out := make([]byte, b.l/2)
	rc := C.bakeBSTSStep2((*C.octet)(unsafe.Pointer(&out[0])), b.state)
	if rc != 0 {
		return nil, errors.New("bee2: bakeBSTSStep2 failed")
	}
	return out, nil
}

// Step3 is called by party A to process M1 and produce M2.
// Output size: 3*l/4 + certLen + 8 bytes, where certLen is A's cert length.
func (b *BakeBSTS) Step3(in []byte) ([]byte, error) {
	outLen := 3*b.l/4 + b.certLen + 8
	out := make([]byte, outLen)

	var inPtr *C.octet
	if len(in) > 0 {
		inPtr = (*C.octet)(unsafe.Pointer(&in[0]))
	}

	rc := C.bakeBSTSStep3((*C.octet)(unsafe.Pointer(&out[0])), inPtr, b.state)
	if rc != 0 {
		return nil, errors.New("bee2: bakeBSTSStep3 failed")
	}
	return out, nil
}

// Step4 is called by party B to process M2 and produce M3.
// Output size: l/4 + certLen + 8 bytes, where certLen is B's cert length.
//
// vala is a C bake_certval_i function pointer (cast to unsafe.Pointer) used
// to validate party A's certificate contained in M2.
func (b *BakeBSTS) Step4(in []byte, vala unsafe.Pointer) ([]byte, error) {
	outLen := b.l/4 + b.certLen + 8
	out := make([]byte, outLen)

	var inPtr *C.octet
	if len(in) > 0 {
		inPtr = (*C.octet)(unsafe.Pointer(&in[0]))
	}

	rc := C.bsts_step4_wrap(
		(*C.octet)(unsafe.Pointer(&out[0])),
		inPtr, C.size_t(len(in)),
		vala, b.state,
	)
	if rc != 0 {
		return nil, errors.New("bee2: bakeBSTSStep4 failed")
	}
	return out, nil
}

// Step5 is called by party A to process M3 and finalise the handshake.
//
// valb is a C bake_certval_i function pointer (cast to unsafe.Pointer) used
// to validate party B's certificate contained in M3.
func (b *BakeBSTS) Step5(in []byte, valb unsafe.Pointer) error {
	var inPtr *C.octet
	if len(in) > 0 {
		inPtr = (*C.octet)(unsafe.Pointer(&in[0]))
	}

	rc := C.bsts_step5_wrap(inPtr, C.size_t(len(in)), valb, b.state)
	if rc != 0 {
		return errors.New("bee2: bakeBSTSStep5 failed")
	}
	return nil
}

// StepG extracts the 32-byte shared session key after the protocol completes.
// Call after Step4 (party B) or Step5 (party A).
func (b *BakeBSTS) StepG() ([]byte, error) {
	key := make([]byte, 32)
	rc := C.bakeBSTSStepG((*C.octet)(unsafe.Pointer(&key[0])), b.state)
	if rc != 0 {
		return nil, errors.New("bee2: bakeBSTSStepG failed")
	}
	return key, nil
}
