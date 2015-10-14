/*
 * This implementation is by Ted Krovetz and was submitted to SUPERCOP and
 * marked as public domain. It was been altered for aarch64.
 */

#include <openssl/chacha.h>

#if defined(__aarch64__)
#include <string.h>
#include <arm_neon.h>

typedef uint32x4_t vec;
typedef uint8x16_t vec8x16;
#define U8P(x) ((uint8_t *)x)
#define ROTV1(x) vextq_u32(x, x, 1)
#define ROTV2(x) vextq_u32(x, x, 2)
#define ROTV3(x) vextq_u32(x, x, 3)

#define ROTW16(x) (vec) vrev32q_u16((uint16x8_t)x)
#define ROTW7(x) vsriq_n_u32(vshlq_n_u32(x, 7), x, 25)
#define ROTW8(x) vsriq_n_u32(vshlq_n_u32(x, 8), x, 24)
#define ROTW12(x) vsriq_n_u32(vshlq_n_u32(x, 12), x, 20)

#define ADDV(a, b) vaddq_u32(a, b)
#define STOREV(a, b) vst1q_u32(a, b)
#define XOR8x16(a, b) veorq_u8(a, b)
#define STORE8x16(a, b) vst1q_u8(a, b)

#define DQROUND_VECTORS(a,b,c,d)                \
    a += b; d ^= a; d = ROTW16(d);              \
    c += d; b ^= c; b = ROTW12(b);              \
    a += b; d ^= a; d = ROTW8(d);               \
    c += d; b ^= c; b = ROTW7(b);               \
    b = ROTV1(b); c = ROTV2(c);  d = ROTV3(d);  \
    a += b; d ^= a; d = ROTW16(d);              \
    c += d; b ^= c; b = ROTW12(b);              \
    a += b; d ^= a; d = ROTW8(d);               \
    c += d; b ^= c; b = ROTW7(b);               \
    b = ROTV3(b); c = ROTV2(c); d = ROTV1(d);           


OPENSSL_EXPORT void
CRYPTO_neon_chacha_core(uint32_t *out, uint32_t *state, size_t len, size_t rounds)
{
	int i, j;
	vec s0, s1, s2, s3, *vi = (vec*)state;
	s0 = vi[0], s1 = vi[1], s2 = vi[2];
	for (j = len/64; j--; ) {
		s3 = vi[3];
		for (i = rounds/2; i--; ) {
			DQROUND_VECTORS(s0,s1,s2,s3);
		}
		STOREV(out, ADDV(vi[0], s0)); out+=4;
		STOREV(out, ADDV(vi[1], s1)); out+=4;
		STOREV(out, ADDV(vi[2], s2)); out+=4;
		STOREV(out, ADDV(vi[3], s3)); out+=4;
		if (++state[12]==0)
			state[13]++;
	}
}

static inline void 
fastXORBytes(uint8_t *dst, uint8_t *a, uint8_t *b, size_t rem)
{
	size_t n = rem/16;
	vec8x16 *v1 = (vec8x16*)(a), *v2 = (vec8x16*)(b);
	if (n > 0) {
		rem -= n*16;
		for (; n--; dst+=16) STORE8x16(dst, XOR8x16(*v1++, *v2++));
	}
	if (rem > 0) {
		a = U8P(v1), b = U8P(v2);
		while (rem--) *dst++ = *a++ ^ *b++;
	}
}

OPENSSL_EXPORT void
CRYPTO_neon_chacha_xor(chacha_state *state, uint8_t *in, uint8_t *out, size_t inlen)
{
	size_t rem, step, j = state->offset;
	while (inlen > 0) {
		rem = CHACHA_STREAM_SIZE - j;
		step = rem <= inlen ? rem : inlen;
		inlen -= step;
		
		fastXORBytes(out, in, (uint8_t*)(state->stream) + j, step);
		out += step;
		in += step;
		j += step;
	
		if (j == CHACHA_STREAM_SIZE) {
			CRYPTO_neon_chacha_core(state->stream, state->state, state->rounds);
			j = state->offset = 0;
		} else {
			state->offset = j;
		}
	}
}

#else
	
// Non-aarch64
OPENSSL_EXPORT void
CRYPTO_neon_chacha_core(uint32_t *keystream, uint32_t *state, size_t len, size_t rounds){}

OPENSSL_EXPORT void
CRYPTO_neon_chacha_xor(chacha_state *cs, uint8_t *in, uint8_t *out, size_t inlen){}

#endif  /* endif defined(__aarch64__) */

void
CRYPTO_chacha_init(uint32_t *state, uint8_t *key, uint8_t *iv) {
	int i, j;
	// constants
	state[0] = 0x61707865;
	state[1] = 0x3320646e;
	state[2] = 0x79622d32;
	state[3] = 0x6b206574;
	// set key
	for(i=0; i<8; i++) {
		state[i+4] = 0;
		for(j=0; j<4; j++){
			state[i+4] += (uint32_t)(key[i*4+j]) << (8*j);
		}
	}
	// block counter
	state[12]=0;
	state[13]=0;
	for(i=0; i<2; i++) {
		state[i+14]=0;
		for(j=0; j<4; j++){
			state[i+14] += (uint32_t)(iv[i*4+j]) << (8*j);
		}
	}
}