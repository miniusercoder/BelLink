/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"crypto/subtle"
	"sync"
	"time"
)

type CookieChecker struct {
	sync.RWMutex
	mac1 struct {
		key [HashSize]byte
	}
	mac2 struct {
		secret        [HashSize]byte
		secretSet     time.Time
		encryptionKey [HashSize]byte
	}
}

type CookieGenerator struct {
	sync.RWMutex
	mac1 struct {
		key [HashSize]byte
	}
	mac2 struct {
		cookie        [HalfHashSize]byte
		cookieSet     time.Time
		hasLastMAC1   bool
		lastMAC1      [HalfHashSize]byte
		encryptionKey [HashSize]byte
	}
}

func (st *CookieChecker) Init(pk NoisePublicKey) {
	st.Lock()
	defer st.Unlock()

	st.mac1.key = bashHashConcat([]byte(WGLabelMAC1), pk[:])
	st.mac2.encryptionKey = bashHashConcat([]byte(WGLabelCookie), pk[:])
	st.mac2.secretSet = time.Time{}
}

func (st *CookieChecker) CheckMAC1(msg []byte) bool {
	st.RLock()
	defer st.RUnlock()

	size := len(msg)
	smac2 := size - HalfHashSize
	smac1 := smac2 - HalfHashSize

	mac1 := bashMAC16(st.mac1.key[:], msg[:smac1])
	return subtle.ConstantTimeCompare(mac1, msg[smac1:smac2]) == 1
}

func (st *CookieChecker) CheckMAC2(msg, src []byte) bool {
	st.RLock()
	defer st.RUnlock()

	if time.Since(st.mac2.secretSet) > CookieRefreshTime {
		return false
	}

	cookie := bashMAC16(st.mac2.secret[:], src)

	smac2 := len(msg) - HalfHashSize
	mac2 := bashMAC16(cookie, msg[:smac2])
	return subtle.ConstantTimeCompare(mac2, msg[smac2:]) == 1
}

func (st *CookieChecker) CreateReply(
	msg []byte,
	recv uint32,
	src []byte,
) (*MessageCookieReply, error) {
	st.RLock()

	// refresh cookie secret

	if time.Since(st.mac2.secretSet) > CookieRefreshTime {
		st.RUnlock()
		st.Lock()
		_, err := rand.Read(st.mac2.secret[:])
		if err != nil {
			st.Unlock()
			return nil, err
		}
		st.mac2.secretSet = time.Now()
		st.Unlock()
		st.RLock()
	}

	cookie := bashMAC16(st.mac2.secret[:], src)

	size := len(msg)
	smac2 := size - HalfHashSize
	smac1 := smac2 - HalfHashSize

	reply := new(MessageCookieReply)
	reply.Type = MessageCookieReplyType
	reply.Receiver = recv

	_, err := rand.Read(reply.Nonce[:])
	if err != nil {
		st.RUnlock()
		return nil, err
	}

	aead := newBashPrgAEADX(st.mac2.encryptionKey)
	aead.Seal(reply.Cookie[:0], reply.Nonce[:], cookie, msg[smac1:smac2])

	st.RUnlock()

	return reply, nil
}

func (st *CookieGenerator) Init(pk NoisePublicKey) {
	st.Lock()
	defer st.Unlock()

	st.mac1.key = bashHashConcat([]byte(WGLabelMAC1), pk[:])
	st.mac2.encryptionKey = bashHashConcat([]byte(WGLabelCookie), pk[:])
	st.mac2.cookieSet = time.Time{}
}

func (st *CookieGenerator) ConsumeReply(msg *MessageCookieReply) bool {
	st.Lock()
	defer st.Unlock()

	if !st.mac2.hasLastMAC1 {
		return false
	}

	var cookie [HalfHashSize]byte

	aead := newBashPrgAEADX(st.mac2.encryptionKey)
	_, err := aead.Open(cookie[:0], msg.Nonce[:], msg.Cookie[:], st.mac2.lastMAC1[:])
	if err != nil {
		return false
	}

	st.mac2.cookieSet = time.Now()
	st.mac2.cookie = cookie
	return true
}

func (st *CookieGenerator) AddMacs(msg []byte) {
	size := len(msg)

	smac2 := size - HalfHashSize
	smac1 := smac2 - HalfHashSize

	mac1 := msg[smac1:smac2]
	mac2 := msg[smac2:]

	st.Lock()
	defer st.Unlock()

	// set mac1
	mac1Bytes := bashMAC16(st.mac1.key[:], msg[:smac1])
	copy(mac1, mac1Bytes)
	copy(st.mac2.lastMAC1[:], mac1)
	st.mac2.hasLastMAC1 = true

	// set mac2

	if time.Since(st.mac2.cookieSet) > CookieRefreshTime {
		return
	}

	mac2Bytes := bashMAC16(st.mac2.cookie[:], msg[:smac2])
	copy(mac2, mac2Bytes)
}
