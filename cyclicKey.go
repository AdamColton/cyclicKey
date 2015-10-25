// Package cyclicKey is a cryptographic experiment.
//
// A cyclic keyset has at least 3 keys. Applying any one key to plain text will
// produce a cipher text. Applying any of the remaining keys to that cipher text
// will produce a new cipher text. When all the keys have been applied (in any
// order) the original plain text is recovered.

package cyclicKey

import (
	"crypto/rand"
)

const p = uint32(257)
const lpr = uint32(3)
const s = p - 1

var invTbl [257]byte  // modulus inversion table
var pmTbl [32896]byte // power modulus table
var loaded = false

// LoadTbl allows explicit preloading of the table. It is not necessary in a
// single threaded context, but to safely call Cipher in a multi-threaded
// context, this should be called prior to any forking.
func LoadTbl() {
	if !loaded {
		loadTbl()
	}
}

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
func powMod(b, e uint32) uint32 {
	pm := uint32(1)
	for e > 0 {
		if e&1 != 0 {
			pm = (pm * b) % p
		}
		e >>= 1
		b = (b * b) % p
	}
	return pm
}

func xorShift(xs1, xs2, xs3, xs4 uint32) (uint32, uint32, uint32, uint32) {
	t, xs1, xs2, xs3 := xs1^(xs1<<11), xs2, xs3, xs4
	xs4 = xs4 ^ (xs4 >> 19) ^ t ^ (t >> 8)
	return xs1, xs2, xs3, xs4
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

// XorShift seeds. These guarentee no more than 4 overlapping rotation values
// in the first 278K rotations for a key length of 10. That's enough for about
// 35M, beyond that, multiple key-sets should be used.
var seed1 = uint32(2339296992)
var seed2 = uint32(2884812447)
var seed3 = uint32(2692626613)
var seed4 = uint32(3191761099)

// Cipher is the encrypt/decrypt function.
// It cannot be called either an encryption or decryption function because often
// the caller does not know what sort of action they are requesting, and often
// one cipher text is being converted to another cipher text.
//
// k32 : A key is a byte slice, but for use they need to be converted to uint32
//       and incremented by 1
// kp  : key-product; product for a given position and key (with inversion)
// cl  : cipher length; length of both input and output
// kl  : byte length of key
// xs1-4 : xorShift values to produce the rotation values
//
// Primative roots form a queue. The queue is one longer than necessary so that
// in the inner loop we can progress the queue without overflowing.
// root: queue of primative roots
// ri  : next primative root index
//
// The most expensive part of the calculation is the modulus operation. But the
// algorithm is working with numbers upto 257 in uint32 space, so it's not
// necessary to perform mod each time. doMod accumulates how many
// multiplications we've done and when it reaches 3 we need to do the mod op.
func Cipher(input, key []byte, invert bool) []byte {
	if !loaded {
		loadTbl()
	}
	//setup
	xs1, xs2, xs3, xs4 := seed1, seed2, seed3, seed4
	kl := len(key)
	k32 := make([]uint32, kl)
	root := make([]uint32, kl+1)
	ri := uint32(1)
	for i := 0; i < kl; i++ {
		root[i], ri = uint32(pmTbl[ri])+1, ri+2
		xs1, xs2, xs3, xs4 = xorShift(xs1, xs2, xs3, xs4)
		k32[i] = ((uint32(key[i]) + 1) * ((xs4 & 255) + 1)) % s
	}
	root[kl], ri = uint32(pmTbl[ri])+1, ri+2

	//main
	cl := len(input)
	output := make([]byte, cl)
	j := 0
	for i := 0; i < cl; i++ {
		// outer loop : iterates over each byte of the message
		doMod := uint8(0)
		kp := uint32(1)
		for j = 0; j < len(key); j++ {
			// inner loop : iterates over each byte of the key
			kp *= uint32(pmTbl[(((root[j]-1)/2)*(257))+k32[j]]) + 1
			doMod++
			if doMod == 3 {
				kp = kp % p
				doMod = 0
			}
			// progress primative root thorugh root queue
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
		// push next primative root on queue
		root[kl], ri = uint32(pmTbl[ri])+1, ri+2
		// do key rotation
		if ri > p-2 {
			ri = uint32(1) //reset root index
			for j = 0; j < kl-1; j++ {
				xs1, xs2, xs3, xs4 = xorShift(xs1, xs2, xs3, xs4)
				k32[j] = ((uint32(key[j]) + 1) * ((xs4 & 255) + 1)) % s
			}
		}
		output[i] = byte((((uint32(input[i]) + 1) * kp) % p) - 1)
	}
	return output
}

// Number of bytes in a single key
var KeyLength = 10

// Generates a set of keys. The size of the set is defined by keys. The length
// of each key is defined by the package variable KeyLength.
func GenerateKeyset(keys int) [][]byte {
	keyset := make([][]byte, keys)
	compoundKey := make([]uint32, KeyLength)

	for i := 0; i < keys-1; i++ {
		keyset[i] = make([]byte, KeyLength)
		_, err := rand.Read(keyset[i])
		if err != nil {
			panic(err)
		}
		for j := 0; j < KeyLength; j += 1 {
			//Technical note, if keys > 16,777,216 compound key could overflow
			compoundKey[j] += uint32(keyset[i][j]) + 1
		}
	}
	keyset[keys-1] = make([]byte, KeyLength)
	for j := 0; j < KeyLength; j += 1 {
		keyset[keys-1][j] += byte((compoundKey[j] % s) - 1)
	}
	return keyset
}
