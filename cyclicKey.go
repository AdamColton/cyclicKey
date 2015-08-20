package crypto

import (
	"crypto/rand"
)

const p = uint32(257)
const lpr = uint32(3)
const s = p - 1

var invTbl [257]byte
var pmTbl [32896]byte
var loaded = false

func loadTbl() {
	for i := uint32(1); i < p; i++ {
		pInv(i)
	}
	// populate by root index first
	// these are of the form
	// pmTbl[(((lpr-1)/2)*(257))+ri] = byte(powMod(lpr,ri) - 1)
	// which simplifies to
	// pmTbl[257+ri] = byte(powMod(lpr,ri) - 1)
	for ri := uint32(1); ri < 257; ri += 2 {
		pmTbl[257+ri] = byte(powMod(lpr, ri) - 1)
	}
	for ri := uint32(1); ri < 257; ri += 2 {
		for e := uint32(0); e < 257; e++ {
			r := powMod(lpr, ri)
			pm := powMod(r, e) - 1
			pmTbl[(((ri-1)/2)*(257))+e] = byte(pm)
		}
	}
	loaded = true
}

// powMod: from http://play.golang.org/p/bm7uZi0zCN
// b,e : base, exponent
// this should not be used elsewere, it is tuned to
// to this algorithm. It has been modified to run in
// constant time.
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

func pInv(ua uint32) uint32 {
	if i := invTbl[ua-1]; i > 0 {
		return uint32(i) + 1
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
	return uint32(x1)
}

func Enc(message, key []byte, invert bool) []byte {
	if !loaded {
		loadTbl()
	}
	l := len(key)
	k32 := make([]uint32, l)
	keyCycle := make([]byte, l)
	root := make([]uint32, l+1)
	r, ri, re := uint32(lpr), uint32(1), l
	for i := 0; i < l; i++ {
		root[i], r, ri = r, uint32(pmTbl[257+ri])+1, ri+2
		k32[i] = uint32(key[i]) + 1
	}
	root[re], r, ri = r, uint32(pmTbl[257+ri])+1, ri+2

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
		}
		root[re], r, ri = r, uint32(pmTbl[257+ri])+1, ri+2
		if ri > p-2 {
			r, ri = uint32(lpr), uint32(3)
			for j = 0; j < len(key); j++ {
				if keyCycle[j] < 255 {
					k32[j] = (k32[j] * 3) % s
					break
				} else {
					keyCycle[j] = 0
					k32[j] = uint32(key[j]) + 1
				}
			}
		}
		c[i] = byte((((uint32(message[i]) + 1) * kp) % p) - 1)
	}
	return c
}

var KeyLength = 10

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
