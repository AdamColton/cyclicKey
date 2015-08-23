// Package cyclicKey is a cryptographic experiment.
//
// A cyclic keyset has at least 3 keys. Applying any one key to plain text
// will produce a cipher text. Applying any of the remaining keys to that
// cipher text will produce a new cipher text. When all the keys have been
// applied (in any order) the original plain text is recovered.

package cyclicKey

import (
	"crypto/rand"
)

const p = uint32(257)
const lpr = uint32(3)
const s = p - 1

var invTbl [257]byte
var pmTbl [32896]byte
var loaded = false

//loadTbl loads invTbl, pmTbl and loaded with their precomputed values
func loadTbl() {
	for i := uint32(1); i < p; i++ {
		pInv(i)
	}
	pmTbl[1] = byte(2)
	for ri := uint32(1); ri < 257; ri += 2 {
		r := uint32(pmTbl[ri]) + 1 // these all get set in the first loop, except pmTbl[1]
		for e := uint32(0); e < 257; e++ {
			pmTbl[(((ri-1)/2)*(257))+e] = byte(powMod(r, e) - 1)
		}
	}
	loaded = true
}

// powMod: from http://play.golang.org/p/bm7uZi0zCN
// b,e : base, exponent
// this has been tuned to this algorithm
// and modified to run in constant time
// to prevent timing attacks
func powMod(b, e uint32) uint32 {
	pm := uint32(1)
	f, fi := uint32(1), uint32(1)
	for i := 0; i < 8; i++ {
		f = e & 1        //flag
		fi = (f + 1) & 1 //flag inverse
		pm = ((pm * (b*f + fi)) % p)
		b = (b * b) % p
		e >>= 1
	}
	return pm
}

//pInv is only used to populate invTbl
//it calculates the inverse of ua with respect to p
func pInv(ua uint32) {
	if invTbl[ua-1] > 0 {
		return
	}
	a := int64(ua)
	b := int64(p)
	var q, x0, x1 int64
	b0 := b
	x0, x1 = 0, 1
	for a > 1 {
		q = a / b
		b, a = a%b, b
		x0, x1 = x1-q*x0, x0
	}
	if x1 < 0 {
		x1 += b0
	}
	invTbl[ua-1] = byte(x1 - 1)
	invTbl[x1-1] = byte(ua - 1)
}

// Cipher is the encrypt/decrypt function.
// It cannot be called either an encryption or decryption function because
// often the caller does not know what sort of action they are requesting,
// and often one cipher text is being converted to another cipher text.
func Cipher(message, key []byte, invert bool) []byte {
	if !loaded {
		loadTbl()
	}
	l := len(key)
	k32 := make([]uint32, l)
	rot, adj := uint32(0), uint32(0)
	stp := make([]uint32, l)
	root := make([]uint32, l+1)
	r, ri, re := uint32(lpr), uint32(1), l
	for i := 0; i < l; i++ {
		root[i], r, ri = r, uint32(pmTbl[ri])+1, ri+2
		k32[i] = uint32(key[i]) + 1
		stp[i] = (2*rot*(uint32(i)+1) + 1)
	}
	root[re], r, ri = r, uint32(pmTbl[ri])+1, ri+2

	l = len(message)
	c := make([]byte, l)
	j := 0
	for i := 0; i < l; i++ {
		doMod := uint8(0)
		kp := uint32(1)
		for j = 0; j < len(key); j++ {
			kp *= uint32(pmTbl[(((root[j]-1)/2)*(257))+k32[j]]) + 1
			doMod++
			if doMod == 3 {
				kp = kp % p
				doMod = 0
			}
			root[j] = root[j+1]
		}
		if doMod != 0 {
			kp = kp % p
		}
		if invert {
			kp = uint32(invTbl[kp-1]) + 1
		} else {
			// this does nothing useful
			// it just takes the same number
			// of operations as the other
			// branch to keep constant time
			doMod = uint8(invTbl[kp-1]) - 1
		}
		root[re], r, ri = r, uint32(pmTbl[ri])+1, ri+2
		// do key rotation
		if ri > p-2 {
			r, ri = uint32(lpr), uint32(3)
			rot += 1
			if rot > 255 {
				rot = 0
				adj += 1
				for j = 0; j < len(key)-1; j++ {
					stp[j] = stp[j+1]
				}
				stp[j] = (2*adj*(uint32(j)+1) + 1)
				for j = 0; j < len(key); j++ {
					k32[j] = ((uint32(key[j]) + 1) * stp[j]) % s
				}
			} else {
				for j = 0; j < len(key); j++ {
					k32[j] = (k32[j] * stp[j]) % s
				}
			}
		}
		c[i] = byte((((uint32(message[i]) + 1) * kp) % p) - 1)
	}
	return c
}

// Number of bytes in a single key
var KeyLength = 10

// Generates a set of keys. The size of the set is defined by keys.
// The length of each key is defined by the package variable KeyLength.
func GenerateKeyset(keys int) [][]byte {
	keyset := make([][]byte, keys+1)
	compoundKey := make([]uint32, KeyLength)
	for i := 0; i < keys; i++ {
		keyset[i] = make([]byte, KeyLength)
		_, err := rand.Read(keyset[i])
		if err != nil {
			panic(err)
		}
		for j := 0; j < KeyLength; j += 1 {
			compoundKey[j] += uint32(keyset[i][j]) + 1
		}
	}
	keyset[keys] = make([]byte, KeyLength)
	for j := 0; j < KeyLength; j += 1 {
		keyset[keys][j] += byte((compoundKey[j] % s) - 1)
	}
	return keyset
}
