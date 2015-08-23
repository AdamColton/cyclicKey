package cyclicKey

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"testing"
)

func TestpowMod(t *testing.T) {
	pm := powMod(111, 222)
	if pm != 120 {
		t.Error(pm)
		t.Error("powMod broken")
	}
}

func TestKeyGeneration(t *testing.T) {
	keys := GenerateKeyset(3)
	if len(keys) != 4 {
		t.Error("Wrong number of keys")
	}
}

func TestCycle(t *testing.T) {
	m := make([]byte, 100000) //needs to be large enough to cascade through a few key cycles
	rand.Read(m)
	c := m
	keys := GenerateKeyset(2)
	for i := 0; i < len(keys); i++ {
		c = Cipher(c, keys[i], i == len(keys)-1)
	}
	if !bytes.Equal(m, c) {
		t.Error(m[190:200])
		t.Error(c[190:200])
		t.Error("Did not cycle")
	}
}

func TestInv(t *testing.T) {
	pInv(111)
	i := uint32(invTbl[111-1]) + 1
	if (i*111)%p != 1 {
		t.Error("pInv error 1, got ")
		t.Error(i)
		t.Error(111)
	}
	pInv(54)
	i = uint32(invTbl[54-1]) + 1
	if (i*54)%p != 1 {
		t.Error("pInv error 2, got")
		t.Error(i)
		t.Error(54)
	}
}

func BenchmarkCycle(b *testing.B) {
	//b.SkipNow()
	loadTbl()
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

func BenchmarkpowMod(b *testing.B) {
	b.SkipNow()
	bt := []byte{0, 0, 0, 0}
	for n := 0; n < b.N; n++ {
		rand.Read(bt)
		x := (uint32(bt[0]) << 8) + uint32(bt[1])
		y := (uint32(bt[2]) << 8) + uint32(bt[3])
		powMod(x, y)
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
