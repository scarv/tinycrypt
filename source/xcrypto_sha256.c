#include <tinycrypt/sha256.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/utils.h>

static void compress(TCSha256State_t s);

int tc_sha256_init(TCSha256State_t s)
{
	/* input sanity check: */
	if (s == (TCSha256State_t) 0) {
		return TC_CRYPTO_FAIL;
	}

	/*
	 * Setting the initial state values.
	 * These values correspond to the first 32 bits of the fractional parts
	 * of the square roots of the first 8 primes: 2, 3, 5, 7, 11, 13, 17
	 * and 19.
	 */
	_set((uint8_t *) s, 0x00, sizeof(*s));
	s->iv[0] = 0x6a09e667;
	s->iv[1] = 0xbb67ae85;
	s->iv[2] = 0x3c6ef372;
	s->iv[3] = 0xa54ff53a;
	s->iv[4] = 0x510e527f;
	s->iv[5] = 0x9b05688c;
	s->iv[6] = 0x1f83d9ab;
	s->iv[7] = 0x5be0cd19;

	return TC_CRYPTO_SUCCESS;
}

int tc_sha256_update(TCSha256State_t s, const uint8_t *data, size_t datalen)
{
	/* input sanity check: */
	if (s == (TCSha256State_t) 0 ||
	    data == (void *) 0) {
		return TC_CRYPTO_FAIL;
	} else if (datalen == 0) {
		return TC_CRYPTO_SUCCESS;
	}

	while (datalen-- > 0) {
		s->leftover[s->leftover_offset++] = *(data++);
		if (s->leftover_offset >= TC_SHA256_BLOCK_SIZE) {
			compress(s);
			s->leftover_offset = 0;
			s->bits_hashed += (TC_SHA256_BLOCK_SIZE << 3);
		}
	}

	return TC_CRYPTO_SUCCESS;
}

int tc_sha256_final(uint8_t *digest, TCSha256State_t s)
{
	unsigned int i;

	/* input sanity check: */
	if (digest == (uint8_t *) 0 ||
	    s == (TCSha256State_t) 0) {
		return TC_CRYPTO_FAIL;
	}

	s->bits_hashed += (s->leftover_offset << 3);

	s->leftover[s->leftover_offset++] = 0x80; /* always room for one byte */
	if (s->leftover_offset > (sizeof(s->leftover) - 8)) {
		/* there is not room for all the padding in this block */
		_set(s->leftover + s->leftover_offset, 0x00,
		     sizeof(s->leftover) - s->leftover_offset);
		compress(s);
		s->leftover_offset = 0;
	}

	/* add the padding and the length in big-Endian format */
	_set(s->leftover + s->leftover_offset, 0x00,
	     sizeof(s->leftover) - 8 - s->leftover_offset);
	s->leftover[sizeof(s->leftover) - 1] = (uint8_t)(s->bits_hashed);
	s->leftover[sizeof(s->leftover) - 2] = (uint8_t)(s->bits_hashed >> 8);
	s->leftover[sizeof(s->leftover) - 3] = (uint8_t)(s->bits_hashed >> 16);
	s->leftover[sizeof(s->leftover) - 4] = (uint8_t)(s->bits_hashed >> 24);
	s->leftover[sizeof(s->leftover) - 5] = (uint8_t)(s->bits_hashed >> 32);
	s->leftover[sizeof(s->leftover) - 6] = (uint8_t)(s->bits_hashed >> 40);
	s->leftover[sizeof(s->leftover) - 7] = (uint8_t)(s->bits_hashed >> 48);
	s->leftover[sizeof(s->leftover) - 8] = (uint8_t)(s->bits_hashed >> 56);

	/* hash the padding and length */
	compress(s);

	/* copy the iv out to digest */
	for (i = 0; i < TC_SHA256_STATE_BLOCKS; ++i) {
		unsigned int t = *((unsigned int *) &s->iv[i]);
		*digest++ = (uint8_t)(t >> 24);
		*digest++ = (uint8_t)(t >> 16);
		*digest++ = (uint8_t)(t >> 8);
		*digest++ = (uint8_t)(t);
	}

	/* destroy the current state */
	_set(s, 0, sizeof(*s));

	return TC_CRYPTO_SUCCESS;
}

static inline void _xc_bop_setup(uint32_t lut) {
    __asm__("csrw uxcrypto, %0" : : "r" (lut));
}

static inline uint32_t _xc_bop(int rd, int rs1, int rs2, int l) {
    int out = rd;

    __asm__("xc.bop %0, %1, %2, %3" :  "+r"(out): "r"(rs1), "r"(rs2), "i"(l));

    return out;
}

static inline uint32_t _xc_sha256_s0 (uint32_t rs1) {
    uint32_t rd;

    __asm__ ("xc.sha256.s0  %0, %1" : "=r"(rd) : "r"(rs1));

    return rd;
}

static inline uint32_t _xc_sha256_s1 (uint32_t rs1) {
    uint32_t rd;

    __asm__ ("xc.sha256.s1  %0, %1" : "=r"(rd) : "r"(rs1));

    return rd;
}

static inline uint32_t _xc_sha256_s2 (uint32_t rs1) {
    uint32_t rd;

    __asm__ ("xc.sha256.s2  %0, %1" : "=r"(rd) : "r"(rs1));

    return rd;
}

static inline uint32_t _xc_sha256_s3 (uint32_t rs1) {
    uint32_t rd;

    __asm__ ("xc.sha256.s3  %0, %1" : "=r"(rd) : "r"(rs1));

    return rd;
}

#define SHA2_256_F0(a,b,c) ( _xc_bop(a,b,c,0) ) //((a&b) | ( (a|b) & c ) )
#define SHA2_256_F1(a,b,c) ( _xc_bop(a,b,c,1) ) //(c ^ ( a & ( b ^ c ) ) )

#define SHA2_256_R(a,b,c,d,e,f,g,h,w,k) {                               \
  uint32_t t_0 = _xc_sha256_s3( e ) + SHA2_256_F1( e, f, g ) + h + w + k; \
  uint32_t t_1 = _xc_sha256_s2( a ) + SHA2_256_F0( a, b, c );             \
                                                                        \
  d +=       t_0;                                                       \
  h  = t_1 + t_0;                                                       \
}

#define U8_TO_U32_BE(r,x,i) {                  \
  (r)  = ( uint32_t )( (x)[ (i) + 3 ] ) <<  0; \
  (r) |= ( uint32_t )( (x)[ (i) + 2 ] ) <<  8; \
  (r) |= ( uint32_t )( (x)[ (i) + 1 ] ) << 16; \
  (r) |= ( uint32_t )( (x)[ (i) + 0 ] ) << 24; \
}

uint32_t SHA2_256_K[] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

static void compress(TCSha256State_t s)
{
    uint8_t workspace[64];

    _xc_bop_setup(0xCAE80000);
    
    uint32_t a = s->iv[0];
    uint32_t b = s->iv[1];
    uint32_t c = s->iv[2];
    uint32_t d = s->iv[3];
    uint32_t e = s->iv[4];
    uint32_t f = s->iv[5];
    uint32_t g = s->iv[6];
    uint32_t h = s->iv[7];

    U8_TO_U32_BE( workspace[  0 ], s->leftover,  0 );
    U8_TO_U32_BE( workspace[  1 ], s->leftover,  4 );
    U8_TO_U32_BE( workspace[  2 ], s->leftover,  8 );
    U8_TO_U32_BE( workspace[  3 ], s->leftover, 12 );
    U8_TO_U32_BE( workspace[  4 ], s->leftover, 16 );
    U8_TO_U32_BE( workspace[  5 ], s->leftover, 20 );
    U8_TO_U32_BE( workspace[  6 ], s->leftover, 24 );
    U8_TO_U32_BE( workspace[  7 ], s->leftover, 28 );
    U8_TO_U32_BE( workspace[  8 ], s->leftover, 32 );
    U8_TO_U32_BE( workspace[  9 ], s->leftover, 36 );
    U8_TO_U32_BE( workspace[ 10 ], s->leftover, 40 );
    U8_TO_U32_BE( workspace[ 11 ], s->leftover, 44 );
    U8_TO_U32_BE( workspace[ 12 ], s->leftover, 48 );
    U8_TO_U32_BE( workspace[ 13 ], s->leftover, 52 );
    U8_TO_U32_BE( workspace[ 14 ], s->leftover, 56 );
    U8_TO_U32_BE( workspace[ 15 ], s->leftover, 60 );

    for (int i = 16; i < 64; i += 1) {
        workspace[i] = _xc_sha256_s1(workspace[i - 2]) + (workspace[i - 7]) +
                       _xc_sha256_s0(workspace[i - 15]) + (workspace[i - 16]);
    }
    
    for (int i =  0; i < 64; i += 8) {
        SHA2_256_R(a, b, c, d, e, f, g, h, workspace[i + 0], SHA2_256_K[i + 0]);
        SHA2_256_R(h, a, b, c, d, e, f, g, workspace[i + 1], SHA2_256_K[i + 1]);
        SHA2_256_R(g, h, a, b, c, d, e, f, workspace[i + 2], SHA2_256_K[i + 2]);
        SHA2_256_R(f, g, h, a, b, c, d, e, workspace[i + 3], SHA2_256_K[i + 3]);
        SHA2_256_R(e, f, g, h, a, b, c, d, workspace[i + 4], SHA2_256_K[i + 4]);
        SHA2_256_R(d, e, f, g, h, a, b, c, workspace[i + 5], SHA2_256_K[i + 5]);
        SHA2_256_R(c, d, e, f, g, h, a, b, workspace[i + 6], SHA2_256_K[i + 6]);
        SHA2_256_R(b, c, d, e, f, g, h, a, workspace[i + 7], SHA2_256_K[i + 7]);
    }
    
    s->iv[0] += a;
    s->iv[1] += b;
    s->iv[2] += c;
    s->iv[3] += d;
    s->iv[4] += e;
    s->iv[5] += f;
    s->iv[6] += g;
    s->iv[7] += h;
}
