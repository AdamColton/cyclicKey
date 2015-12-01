package cyclicKey

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
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
		t.Error(m[190:200])
		t.Error(c[190:200])
		t.Error("Did not cycle")
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
	var x uint32
	for n := 0; n < b.N; n++ {
		rand.Read(bt)
		x = (uint32(bt[0]) << 8) + uint32(bt[1])
		x = (uint32(bt[2]) << 8) + uint32(bt[3])
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
