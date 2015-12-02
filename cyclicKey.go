/*
Package cyclicKey is a cryptographic experiment.

A cyclic keyset has at least 3 keys. Applying any one key to plain text will
produce a cipher text. Applying any of the remaining keys to that cipher text
will produce a new cipher text. When all the keys have been applied (in any
order) the original plain text is recovered.
*/

package cyclicKey

import (
	"crypto/rand"
)

const p = uint32(257)
const lpr = uint32(3)
const s = p - 1

// XorShift seeds. These guarentee no more than 4 overlapping rotation values
// in the first 278K rotations for a key length of 10. That's enough for about
// 35MB of data, beyond that, multiple key-sets should be used.
var seed1 = uint32(2339296992)
var seed2 = uint32(2884812447)
var seed3 = uint32(2692626613)
var seed4 = uint32(3191761099)

// xorShift is a pseudo random generator it is used to produce a constant key
// rotation. It is by no means cryptographically secure and is not used in any
// manor that would rely on it being secure
func xorShift(xs1, xs2, xs3, xs4 uint32) (uint32, uint32, uint32, uint32) {
	t, xs1, xs2, xs3 := xs1^(xs1<<11), xs2, xs3, xs4
	xs4 = xs4 ^ (xs4 >> 19) ^ t ^ (t >> 8)
	return xs1, xs2, xs3, xs4
}

// Cipher is the encrypt/decrypt function.
// It cannot be called either an encryption or decryption function because often
// the caller does not know what sort of action they are requesting, and often
// one cipher text is being converted to another cipher text.
//
// k32 : A key is stored and transmitted as a byte slice, but for use it needs
//       to be converted to uint32 and incremented by 1
// kp  : key-product; product for a given position and key (with inversion)
// cl  : cipher length; length of both input and output
// kl  : length of key in bytes
// xs1-4 : xorShift values to produce the rotation values, xs4 is used as the
//         random value
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
	//setup
	xs1, xs2, xs3, xs4 := seed1, seed2, seed3, seed4
	kl := len(key)
	k32 := make([]uint32, kl)
	root := make([]uint32, kl+1)
	ri := uint32(1)
	for i := 0; i < kl; i++ {
		root[i], ri = ((pmTbl[ri]-1)/2)*257, ri+2
		xs1, xs2, xs3, xs4 = xorShift(xs1, xs2, xs3, xs4)
		k32[i] = ((uint32(key[i]) + 1) * ((xs4 & 255) + 1)) % s
	}
	root[kl], ri = ((pmTbl[ri]-1)/2)*257, ri+2

	//main
	cl := len(input)
	output := make([]byte, cl)
	j := 0
	for i := 0; i < cl; i++ {
		// outer loop : iterates over each byte of the message
		doMod := uint8(0)
		kp := uint32(1)
		for j = 0; j < len(key); j++ {
			// kp = f(kp 0:256, root 0:127, key 1:256)
			// inner loop : iterates over each byte of the key
			kp *= pmTbl[root[j]+k32[j]]
			if doMod == 2 {
				kp = kp % p
				doMod = 0
			} else {
				doMod++
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
		root[kl], ri = ((pmTbl[ri]-1)/2)*257, ri+2
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
