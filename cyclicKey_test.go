package cyclicKey

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"math"
	"testing"
)

func TestKeyGeneration(t *testing.T) {
	keys := GenerateKeyset(3)
	if len(keys) != 3 {
		t.Error("Wrong number of keys")
	}
}

func TestCycle(t *testing.T) {
	m := make([]byte, 100000) //needs to be large enough to cascade through a few key cycles
	rand.Read(m)
	c := m
	keys := GenerateKeyset(3)
	for i := 0; i < len(keys); i++ {
		c = Cipher(c, keys[i], i == len(keys)-1)
	}
	if !bytes.Equal(m, c) {
		t.Error(m[180:200])
		t.Error(c[180:200])
		t.Error("Did not cycle")
		t.Error(m[0:20])
		t.Error(c[0:20])
	}
}

func TestPrintRoots(t *testing.T) {
	expectRoots := [...]uint32{
		3, 27, 243, 131, 151, 74, 152, 83, 233, 41, 112, 237, 77, 179, 69, 107, 192,
		186, 132, 160, 155, 110, 219, 172, 6, 54, 229, 5, 45, 148, 47, 166, 209, 82,
		224, 217, 154, 101, 138, 214, 127, 115, 7, 63, 53, 220, 181, 87, 12, 108,
		201, 10, 90, 39, 94, 75, 161, 164, 191, 177, 51, 202, 19, 171, 254, 230, 14,
		126, 106, 183, 105, 174, 24, 216, 145, 20, 180, 78, 188, 150, 65, 71, 125,
		97, 102, 147, 38, 85, 251, 203, 28, 252, 212, 109, 210, 91, 48, 175, 33, 40,
		103, 156, 119, 43, 130, 142, 250, 194, 204, 37, 76, 170, 245, 149, 56, 247,
		167, 218, 163, 182, 96, 93, 66, 80, 206, 55, 238, 86,
	}
	for i := 0; i < 127; i++ {
		// r[i]^e % p == pmTbl[i*257 + e]
		if expectRoots[i] != pmTbl[i*257+1] {
			t.Error("Incorrect value in pmTbl")
		}
	}
}

func TestRandomUntilRepeat(t *testing.T) {
	t.SkipNow() // kind of slow, so skip by default
	/*
	   This shows that the xorShift pseudo-random generator seeded with the a
	   nothing-up-my-sleeve number does not have more than a 30% overlap in the
	   first 10,000 positions.
	*/
	xs1, xs2, xs3, xs4 := seed1, seed2, seed3, seed4
	past := make([][]byte, 0)
	l := make([]byte, 10)
	checkLen := 117000
	for count := 0; count < checkLen; count++ {
		for i := 0; i < 10; i++ {
			xs1, xs2, xs3, xs4 = xorShift(xs1, xs2, xs3, xs4)
			l[i] = byte(xs4 & 255)
		}
		for i := 0; i < len(past); i++ {
			c := 0
			for j := 0; j < 10; j++ {
				if past[i][j] == l[j] {
					c++
					if c > 3 {
						t.Error(count)
						return
					}
				}
			}
		}
		ln := len(past)
		past = append(past, make([]byte, 10))
		for i := 0; i < 10; i++ {
			past[ln][i] = l[i]
		}
	}
}

func BenchmarkCycle(b *testing.B) {
	//b.SkipNow()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		m := make([]byte, 100000)
		rand.Read(m)
		c := m
		keys := GenerateKeyset(4)
		for i := 0; i < len(keys)-1; i++ {
			c = Cipher(c, keys[i], false)
		}
		c = Cipher(c, keys[len(keys)-1], true)
	}
}

// Comparison to see how much overhead the rand
// operations in BenchmarkpowMod are consuming
func BenchmarkRand(b *testing.B) {
	b.SkipNow()
	bt := []byte{0, 0, 0, 0}
	var x uint16
	for n := 0; n < b.N; n++ {
		rand.Read(bt)
		x = (uint16(bt[0]) << 8) + uint16(bt[1])
		x = (uint16(bt[2]) << 8) + uint16(bt[3])
	}
	if false {
		b.Log(x) //or it complains about unused x
	}
}

func BenchmarkAES(b *testing.B) {
	l := 100000
	for n := 0; n < b.N; n++ {
		m := make([]byte, l)
		c := make([]byte, l)
		k := make([]byte, 16)
		rand.Read(m)
		rand.Read(k)
		a, _ := aes.NewCipher(k)
		for i := 0; i < 5; i++ {
			a.Encrypt(c, m)
		}
	}
}

// TestBreakIt is a demonstration of an attack on this algorithm.
// this completely breaks the algorithm - don't use it
// for demonstration purposes, we're just going to use a 2 byte key
// and recover one byte.
func TestBreakIt(t *testing.T) {
	// setup key and message
	m := make([]byte, 5)
	rand.Read(m)
	reset := KeyLength
	KeyLength = 2
	keys := GenerateKeyset(3)
	KeyLength = reset

	// find the keys that were actually used
	// note that k32 will not be used again until
	// the final check
	xs1, xs2, xs3, xs4 := seed1, seed2, seed3, seed4
	k32 := make([]uint32, len(keys[0]))
	for i, k := range keys[0] {
		xs1, xs2, xs3, xs4 = xorShift(xs1, xs2, xs3, xs4)
		k32[i] = ((uint32(k) + 1) * ((xs4 & 255) + 1)) % s
	}

	mi_256 := make([]uint32, 258) // modular inversion for 256
	// I know this is super lazy, I did it the right way once, but this is faster to write
	for i := uint32(1); i < 256; i++ {
		for j := i; j < 256; j++ {
			if (i*j)%256 == 1 {
				if mi_256[i] == 0 {
					mi_256[i] = j
				}
				if mi_256[j] == 0 {
					mi_256[j] = i
				}
			}
		}
	}

	// compute the discrete log table
	// I'm using 55 as a base, any primitive root will work
	dlog := make([]uint32, 258)
	for e := uint32(1); e < 256; e++ {
		dlog[pmTbl[55*257+e]] = e
	}

	// get the cipher text
	c := Cipher(m, keys[0], false)

	// This is the start of the attack
	// convert ciphertext and message into uint32 for ease of use
	m32 := make([]uint32, len(m))
	c32 := make([]uint32, len(m))
	for i := 0; i < len(m); i++ {
		m32[i] = uint32(m[i]) + 1
		c32[i] = uint32(c[i]) + 1
	}

	// find the key products used
	kp := make([]uint32, len(m))
	for i, v := range m {
		vi := uint32(invTbl[v]) + 1
		kp[i] = (vi * c32[i]) % p
	}

	// The math behind the attack
	// k0 * dlog(r1) + k0 * dlog(r2) = dlog(kp0)
	// k0 * dlog(r2) + k0 * dlog(r3) = dlog(kp1)
	// --- dlog Note (this confused me)
	// ( 3^10 = 196 )             % 257
	// ( 10*dlog(3) = dlog(196) ) % 256
	// ( 10*256 = 226 ) % 256
	// once the dlog's are applied we switch to the toitent of 257, which is 256
	// --- Which we'll treat as
	// ( A*x1 + B*x2 = Y1 ) % 256
	// ( C*x1 + D*x2 = Y2 ) % 256
	// --- lin alg
	// A B = Y1
	// C D = Y2
	//
	// 1 A'*B = A'*Y1
	// 1 C'*D = C'*Y2
	//
	// 1 A'*B        = A'*Y1
	// 0 C'*D - A'*B = C'*Y2 - A'*Y1
	//
	// From here, we could continue with the linear algebra, but it actully gets
	// really tricky. In GF(256), it is only possible to take the modular
	// inversion of an odd number. But dlog(root) will always be odd (for 257).
	// And the modular inversion will also always be odd. But that means that
	// (C'*D - A'*B) % 256
	// will always be even. It's possible to solve this with the linear algebra,
	// but it's tricky.
	//
	// However, at this point, it's narrowed down enough that we can try all the
	// values for one key. Even if we have to do this for each key, we're still
	// O(n), where n is the length of the key.

	r1 := pmTbl[1]
	r2 := pmTbl[1*257+1]
	r3 := pmTbl[2*257+1]

	A := dlog[r1]
	B := dlog[r2]
	C := dlog[r2]
	D := dlog[r3]
	Y1 := dlog[kp[0]]
	Y2 := dlog[kp[1]]

	Ai := mi_256[A]
	Ci := mi_256[C]

	if Ai == 0 || Ci == 0 {
		t.Error("Ai or Ci is 0")
		return
	}

	E := (int(Ci*D) - int(Ai*B)) % 256
	if E < 0 {
		E += 256
	}
	t3 := (int(Ci*Y2) - int(Ai*Y1)) % 256
	if t3 < 0 {
		t3 += 256
	}

	// this attack narrows it down to 4 keys
	// if the matrix was larger than 2x2, it would get the right key
	tries := 4

	for k2 := uint32(1); k2 < 257; k2++ {
		if uint32(E)*k2%256 == uint32(t3) {
			k1 := (int(Ai*Y1) - int(Ai*B*k2)) % 256
			if k1 < 0 {
				k1 += 256
			}

			tries--
			if k1 == int(k32[0]) && k2 == k32[1] {
				// we got it
				return
			}
			if tries == 0 {
				break
			}
		}
	}
	t.Error("Failed to recover key")

}
