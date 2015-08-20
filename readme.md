## Cyclic Key Cryptography
Let's start with: **THIS IS AN EXPERIMENT**, it is not a proven cipher and I am not a professional cryptographer. Both the algorithm implementation are untested. Do not use them in any scenario involving real security. This code is provided to demonstrate a concept.

It's also entirely possible that this is an old idea and my Google-fu simply was not powerful enough to find it. This is particularly likely because the terms correctly associated with this concept are "group cascade" but any combination of those terms with things like key or cryptography brings up textually similar, but conceptually different results (cryptographic group keys, sql group cascades).

### Motivation
My specific motivation regards Onion Routing, but this cipher could have many other uses. I wanted to assign a one time use key to every node in an onion-path (embedded within the onion package) so that a message could be mutated at each step and return to it's original state when all keys had been applied (with the intended recipient holding the last key). It was important that no two keys could be proven to belong to the same set (unless they were identical, or the entire set is known). And that no two message states could be shown to be instance of the message. More specifically, because every node sees two states (incoming and out going) the combination of a message-state and key cannot be shown to correspond to any other message-state except the one generated by applying the key.

### The Math
I cannot really call this original, it's a slight variation on the [Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange), though I originally came to the idea through the [Pohlig-Hellman Algorithm](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm) via [this post](http://crypto.stackexchange.com/questions/25065/combining-cascaded-encryption-keys-into-one-key).

The algorithm is based on the discrete log problem and uses much of the same math as other ciphers relying on that mechanism. In the following example, ^-1 refers to modular inversion.
```
-- Start with
p : a prime
r : a primitive root of p
m : a message in (1, p-1)
-- Choose
x,y : keys in (1, p-1)
i : inversion direction, a bool
-- Compute
c : the compound key
c = (x+y) % (p-1)
-- Cipher
c1 = (m * (r^x)) % p
c1 = i ?: c1 ^ -1

c2 = (c1 * (r^y)) % p
c2 = i ?: c2 ^ -1

c3 = (c2 * (r^y)) % p
c3 = !i ?: c3 ^ -1
-- Result
c3 == m
```
The inversion flag, i, would be distributed with (or encoded so it can be extracted from) the key. Because this is randomly chosen, it is not an indication of which key is the compound key. The compound key is indistinguishable.

This works because
```
((x^a) % y) * ((x^b) % y) == (x ^ (a+b)) % y)
for any values of a,b,x and y

And
(r ^ (a+b)) % p == (r ^ ((a+b)%(p-1))) % p
for any values of a and b, and any p where r is a primitive
It may also work for any values, but those are the only ones I've confirmed so far
```

### Implementation
I chose a fixed prime of 257 (2^8 + 1). This has many advantageous properties for the algorithm. The key and message must be broken up into segments that lie between 1 and p-1. Using 257 allows to take the bytes of a message (cast to a larger type) and add 1. This ensures we are always in the necessary range. Another advantage is that the algorithm for finding cyclic routes involves finding the greatest common denominator between a number (the root index) and p-1. Because p-1 = 2^8, we can bypass this check by starting the root index at 1 and incrementing by 2. The final advantage is that all necessary computations are small enough to pre-compute and cache. This provides an enormous gain in speed. The cache consumes 32896B.

I will not provide a detailed explanation here, but because of the way I wish to apply this to onion-routing, the cryptographic requirements are lower than usual, but a premium is placed on overhead and speed. For this reason, I've chosen a key of 2^80 and may even reduce that to 2^64. This is why the KeyLength defaults to 10 bytes. This variable is intentionally exposed, the algorithm works with any number of bytes as the key.

Full implementation, I will use some list comprehensions in the notation. I am not notating type conversions, so in the cases that an operation could overflow a type, assume that we've made the proper conversions (looking at the source code will show this). This also does not show the key rotation which will be described after.
```
-- Given
p : 257
s : p-1
m : byte array
r : byte array of primitive roots
-- Generate Keys
n : number of keys
l : length of each key
i : RAND_BOOL // inversion
k = [ [ RAND_BYTE foreach l] foreach n] // two dimensional byte array size n x l
ki = [i foreach n]
k[l] = [ sum([k[x][y] for x in n]) % (p-1) for y in l ]
ki[l] = !i
-- Cipher Algorithm
Arguments(
  m: message // 1d byte array
  k: key // 1d byte array (we're doing this step for one key)
  i: inversion //bool
)
c : byte array with len(c) = len(m)

for x in len(m):
  kp = 1 // key product
  for y in len(k):
    kp *= (r[x+y] ^ k[y]) % p
  kp = i ?: kp^-1
  c[x] = (m*kp) % p
```

The final details is the key rotation. In the above code, if x+y > 255, kp will repeat. This will easily break the security we're after. This only allows us to encipher 127 bytes. The keys need to be rotated in such a way that the output will not repeat but the relationship between the original keys is maintained. The solution is to multiply the keys by a constant, using 3 will cycle through every value in (1, p-1) before repeating. This still only gives us 256*127 (32512) bytes. We can rotate the keys independently. Just multiplying the last key by 3 prevents the output from repeating. Doing that until the last key repeats, then multiplying the second to last key gives us the ability to encipher a substantial amount of data, 127 * 256^keyBytes.

However, the key rotation was the last detail I worked out and it has not even been tested to the degree that I'm capable of. 

### Performance
The algorithm runs in O(n) time, n being message length.

Running the benchmarks on an Ubuntu server, the cyclic key cipher performed 2.4x slower than AES. I consider this to be more than acceptable. The AES implementation in Go has been highly optimized. This version of the cyclic key cipher has only undergone a limited amount of optimization. Most of which has been achieved with lookup tables. With Go's bounds checking, this will incur notable overhead. I would like to try moving this into cgo to see what the performance gain is. However, even at 2.4x slower, the cyclic key cipher performs an operation that cannot be done with AES (at least not to my knowledge) and the performance loss is there for acceptable if that operation is necessary.