/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/subtle"
	"errors"

	bee2go "bee2go"
)

/* KDF related functions.
 * Bash PRG-based Key Derivation Function replacing HKDF-BLAKE2s.
 * Semantics match RFC 5869 but using bash PRG as the MAC primitive.
 */

func HMAC1(sum *[HashSize]byte, key, in0 []byte) {
	bashMAC(sum, key, in0)
}

func HMAC2(sum *[HashSize]byte, key, in0, in1 []byte) {
	bashMAC(sum, key, in0, in1)
}

func KDF1(t0 *[HashSize]byte, key, input []byte) {
	HMAC1(t0, key, input)
	HMAC1(t0, t0[:], []byte{0x1})
}

func KDF2(t0, t1 *[HashSize]byte, key, input []byte) {
	var prk [HashSize]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	setZero(prk[:])
}

func KDF3(t0, t1, t2 *[HashSize]byte, key, input []byte) {
	var prk [HashSize]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	HMAC2(t2, prk[:], t1[:], []byte{0x3})
	setZero(prk[:])
}

func isZero(val []byte) bool {
	acc := 1
	for _, b := range val {
		acc &= subtle.ConstantTimeByteEq(b, 0)
	}
	return acc == 1
}

/* This function is not used as pervasively as it should because this is mostly impossible in Go at the moment */
func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}

// bignCurve256v1OID is the OID for the bign-curve256v1 parameter set (l=128).
const bignCurve256v1OID = "1.2.112.0.2.0.34.101.45.3.1"

var errInvalidPublicKey = errors.New("invalid public key")

// newPrivateKey generates a new bign private key using bignKeypairGen.
// The underlying bign library ensures the key is in the valid range.
func newPrivateKey() (sk NoisePrivateKey, err error) {
	params, err := bee2go.NewBignParamsStd(bignCurve256v1OID)
	if err != nil {
		return sk, err
	}
	defer params.Free()

	privKey, _, err := bee2go.BignKeypairGen(params)
	if err != nil {
		return sk, err
	}
	copy(sk[:], privKey)
	return sk, nil
}

// publicKey derives the bign public key from the private key.
func (sk *NoisePrivateKey) publicKey() (pk NoisePublicKey) {
	params, err := bee2go.NewBignParamsStd(bignCurve256v1OID)
	if err != nil {
		panic("bee2: publicKey: " + err.Error())
	}
	defer params.Free()

	pubKey, err := bee2go.BignPubkeyCalc(params, sk[:])
	if err != nil {
		panic("bee2: publicKey: " + err.Error())
	}
	copy(pk[:], pubKey)
	return pk
}

// sharedSecret computes the bign Diffie-Hellman shared secret.
func (sk *NoisePrivateKey) sharedSecret(pk NoisePublicKey) (ss [NoisePublicKeySize]byte, err error) {
	params, err := bee2go.NewBignParamsStd(bignCurve256v1OID)
	if err != nil {
		return ss, errInvalidPublicKey
	}
	defer params.Free()

	shared, err := bee2go.BignDH(params, sk[:], pk[:], NoisePublicKeySize)
	if err != nil {
		return ss, errInvalidPublicKey
	}
	if isZero(shared) {
		return ss, errInvalidPublicKey
	}
	copy(ss[:], shared)
	return ss, nil
}
