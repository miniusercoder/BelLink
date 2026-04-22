/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/hex"
	"testing"
)

type KDFTest struct {
	key   string
	input string
	t0    string
	t1    string
	t2    string
}

func assertEquals(t *testing.T, a, b string) {
	if a != b {
		t.Fatal("expected", a, "=", b)
	}
}

func TestKDF(t *testing.T) {
	tests := []KDFTest{
		{
			key:   "746573742d6b6579",
			input: "746573742d696e707574",
			t0:    "dbfad6f8e6d22e7f321e5fe7d0ebd4815aff27f53cbc22a7d136d5465516fd38",
			t1:    "a1c948e33a09f916f249d665eff13d7313700e5dc407bb56a503d54daa9e29a9",
			t2:    "e14eadd9c68a95706d6960e0003e53ba4f25cd534aba97e136f0e9e458e1a359",
		},
		{
			key:   "776972656775617264",
			input: "776972656775617264",
			t0:    "46eb98d746a5757ae8e40dae2e33d0094c1d52f9958fdddcd28a889d4de4c43d",
			t1:    "08ea31d49914891eafa5aa361e6fdee42bdde3fbfd5e885cb237b70bc8afa183",
			t2:    "3c05f9102adf94c836944730aff56d59f53cdaeb4cfa9f3e2ca165976e1b2adb",
		},
		{
			key:   "",
			input: "",
			t0:    "11e4d34017a98cbd37a32028858d73410274a3ae2be8155b5ba1772a69a39064",
			t1:    "25e91f2a6ff3be9cba39c399c301e9d8a3f796019b03a29289eda82d83f401ad",
			t2:    "694d46f46a82b5a070ab8c747387703441317cfa1fee0ae8d4b2a591a0fbe3dc",
		},
	}

	var t0, t1, t2 [HashSize]byte

	for _, test := range tests {
		key, _ := hex.DecodeString(test.key)
		input, _ := hex.DecodeString(test.input)
		KDF3(&t0, &t1, &t2, key, input)
		t0s := hex.EncodeToString(t0[:])
		t1s := hex.EncodeToString(t1[:])
		t2s := hex.EncodeToString(t2[:])
		assertEquals(t, t0s, test.t0)
		assertEquals(t, t1s, test.t1)
		assertEquals(t, t2s, test.t2)
	}

	for _, test := range tests {
		key, _ := hex.DecodeString(test.key)
		input, _ := hex.DecodeString(test.input)
		KDF2(&t0, &t1, key, input)
		t0s := hex.EncodeToString(t0[:])
		t1s := hex.EncodeToString(t1[:])
		assertEquals(t, t0s, test.t0)
		assertEquals(t, t1s, test.t1)
	}

	for _, test := range tests {
		key, _ := hex.DecodeString(test.key)
		input, _ := hex.DecodeString(test.input)
		KDF1(&t0, key, input)
		t0s := hex.EncodeToString(t0[:])
		assertEquals(t, t0s, test.t0)
	}
}
