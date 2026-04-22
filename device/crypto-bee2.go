/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"

	bee2go "bee2go"
)

// Size constants for bee2-based primitives.
// These are chosen to match the original WireGuard constants so that
// only the DH public key size changes (32 → 64 bytes).
const (
	HashSize       = 32 // bash hash output for l=128 (l/4 bytes)
	HalfHashSize   = 16 // half of HashSize, used for MAC1/MAC2 fields
	AEADTagSize    = 16 // bash PRG authentication tag
	AEADNonceSize  = 12 // bash PRG nonce (ann) size — multiple of 4, ≤ 60
	AEADNonceSizeX = 24 // extended nonce for cookie encryption
)

// ────────────────────────────────────────────────────────────────────────────
// Noise protocol initialization
// ────────────────────────────────────────────────────────────────────────────

// init computes the InitialChainKey and InitialHash used by the Noise handshake.
// NoiseConstruction and WGIdentifier are declared in noise-protocol.go.
func init() {
	result, err := bee2go.BashHash(128, []byte(NoiseConstruction))
	if err != nil {
		panic("bee2: init: " + err.Error())
	}
	copy(InitialChainKey[:], result)
	mixHash(&InitialHash, &InitialChainKey, []byte(WGIdentifier))
}

// ────────────────────────────────────────────────────────────────────────────
// KDF helpers: bash PRG as HMAC substitute
// ────────────────────────────────────────────────────────────────────────────

// bashMAC computes a HashSize-byte bash PRG MAC:
//
//	init(key) → absorb(inputs[0]) → … → absorb(inputs[n-1]) → squeeze(HashSize)
func bashMAC(sum *[HashSize]byte, key []byte, inputs ...[]byte) {
	prg, err := bee2go.NewBashPrg(128, 1, nil, key)
	if err != nil {
		panic("bee2: bashMAC: " + err.Error())
	}
	defer prg.Free()
	for _, d := range inputs {
		prg.Absorb(d)
	}
	copy(sum[:], prg.Squeeze(HashSize))
}

// bashHashConcat hashes the concatenation of parts using BashHash (l=128).
// Used for key derivation from labels and public keys (e.g. cookie MAC keys).
func bashHashConcat(parts ...[]byte) [HashSize]byte {
	var total int
	for _, p := range parts {
		total += len(p)
	}
	buf := make([]byte, 0, total)
	for _, p := range parts {
		buf = append(buf, p...)
	}
	result, err := bee2go.BashHash(128, buf)
	if err != nil {
		panic("bee2: bashHashConcat: " + err.Error())
	}
	var out [HashSize]byte
	copy(out[:], result)
	return out
}

// bashMAC16 computes a 16-byte bash PRG MAC over a single data slice.
// Used for cookie MAC1/MAC2 computations.
func bashMAC16(key, data []byte) []byte {
	prg, err := bee2go.NewBashPrg(128, 1, nil, key)
	if err != nil {
		panic("bee2: bashMAC16: " + err.Error())
	}
	defer prg.Free()
	prg.Absorb(data)
	return prg.Squeeze(HalfHashSize)
}

// mixHash hashes h||data using BashHash and writes the result to dst.
func mixHash(dst, h *[HashSize]byte, data []byte) {
	src := make([]byte, HashSize+len(data))
	copy(src, h[:])
	copy(src[HashSize:], data)
	result, err := bee2go.BashHash(128, src)
	if err != nil {
		panic("bee2: mixHash: " + err.Error())
	}
	copy(dst[:], result)
}

// ────────────────────────────────────────────────────────────────────────────
// AEAD: BashPrg implementing crypto/cipher.AEAD
// ────────────────────────────────────────────────────────────────────────────

var errAuthFailure = errors.New("bee2: AEAD authentication failure")

// bashPrgAEAD implements cipher.AEAD with a 12-byte nonce using bash PRG.
//
// Bash PRG is a duplex sponge: Encrypt(pt→ct) and Decrypt(ct→pt) both absorb
// the ciphertext into the state, so Squeeze produces the same tag in both
// directions. This allows single-pass authenticated decryption.
type bashPrgAEAD struct {
	key [HashSize]byte
}

func newBashPrgAEAD(key [HashSize]byte) cipher.AEAD {
	a := &bashPrgAEAD{}
	copy(a.key[:], key[:])
	return a
}

func (a *bashPrgAEAD) NonceSize() int { return AEADNonceSize }
func (a *bashPrgAEAD) Overhead() int  { return AEADTagSize }

func (a *bashPrgAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	prg, err := bee2go.NewBashPrg(128, 1, nonce, a.key[:])
	if err != nil {
		panic("bee2: bashPrgAEAD.Seal: " + err.Error())
	}
	defer prg.Free()

	prg.Absorb(additionalData)

	ct := make([]byte, len(plaintext))
	copy(ct, plaintext)
	prg.Encrypt(ct)

	tag := prg.Squeeze(AEADTagSize)
	dst = append(dst, ct...)
	dst = append(dst, tag...)
	return dst
}

func (a *bashPrgAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < AEADTagSize {
		return nil, errAuthFailure
	}
	ct := ciphertext[:len(ciphertext)-AEADTagSize]
	tag := ciphertext[len(ciphertext)-AEADTagSize:]

	prg, err := bee2go.NewBashPrg(128, 1, nonce, a.key[:])
	if err != nil {
		return nil, errAuthFailure
	}
	defer prg.Free()

	prg.Absorb(additionalData)

	pt := make([]byte, len(ct))
	copy(pt, ct)
	prg.Decrypt(pt)

	expectedTag := prg.Squeeze(AEADTagSize)
	if subtle.ConstantTimeCompare(tag, expectedTag) != 1 {
		return nil, errAuthFailure
	}
	return append(dst, pt...), nil
}

// bashPrgAEADX implements cipher.AEAD with a 24-byte nonce (for cookie encryption).
type bashPrgAEADX struct {
	key [HashSize]byte
}

func newBashPrgAEADX(key [HashSize]byte) cipher.AEAD {
	a := &bashPrgAEADX{}
	copy(a.key[:], key[:])
	return a
}

func (a *bashPrgAEADX) NonceSize() int { return AEADNonceSizeX }
func (a *bashPrgAEADX) Overhead() int  { return AEADTagSize }

func (a *bashPrgAEADX) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	prg, err := bee2go.NewBashPrg(128, 1, nonce, a.key[:])
	if err != nil {
		panic("bee2: bashPrgAEADX.Seal: " + err.Error())
	}
	defer prg.Free()

	prg.Absorb(additionalData)

	ct := make([]byte, len(plaintext))
	copy(ct, plaintext)
	prg.Encrypt(ct)

	tag := prg.Squeeze(AEADTagSize)
	dst = append(dst, ct...)
	dst = append(dst, tag...)
	return dst
}

func (a *bashPrgAEADX) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < AEADTagSize {
		return nil, errAuthFailure
	}
	ct := ciphertext[:len(ciphertext)-AEADTagSize]
	tag := ciphertext[len(ciphertext)-AEADTagSize:]

	prg, err := bee2go.NewBashPrg(128, 1, nonce, a.key[:])
	if err != nil {
		return nil, errAuthFailure
	}
	defer prg.Free()

	prg.Absorb(additionalData)

	pt := make([]byte, len(ct))
	copy(pt, ct)
	prg.Decrypt(pt)

	expectedTag := prg.Squeeze(AEADTagSize)
	if subtle.ConstantTimeCompare(tag, expectedTag) != 1 {
		return nil, errAuthFailure
	}
	return append(dst, pt...), nil
}
