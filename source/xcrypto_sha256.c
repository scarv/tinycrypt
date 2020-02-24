#include <tinycrypt/sha256.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/utils.h>

static void compress(unsigned int *iv, const uint8_t *data);

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
			compress(s->iv, s->leftover);
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
		compress(s->iv, s->leftover);
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
	compress(s->iv, s->leftover);

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

static void compress(TCSha256State_t s, const uint8_t *data)
{
    //
    // b0 = F0 = (a & b) | ((a|b)&c)
    // b1 = F1 = (c ^ (a & (b ^ c) ))
    //
    // A  B  C | b0  b1
    // --------|----------
    // 0  0  0 | 0   0
    // 0  0  1 | 0   1
    // 0  1  0 | 0   0
    // 0  1  1 | 1   1
    // 1  0  0 | 0   0
    // 1  0  1 | 1   0
    // 1  1  0 | 1   1
    // 1  1  1 | 1   1
    //
    // b0 = 11101000 - 0xE8
    // b1 = 11001010 - 0xCA
    _xc_bop_setup(0xCAE80000);
    
    uint32_t a = s->iv[0];
    uint32_t b = s->iv[1];
    uint32_t c = s->iv[2];
    uint32_t d = s->iv[3];
    uint32_t e = s->iv[4];
    uint32_t f = s->iv[5];
    uint32_t g = s->iv[6];
    uint32_t h = s->iv[7];

    // TODO
    
    U8_TO_U32_BE( s->W[  0 ], x,  0 );
    U8_TO_U32_BE( s->W[  1 ], x,  4 );
    U8_TO_U32_BE( s->W[  2 ], x,  8 );
    U8_TO_U32_BE( s->W[  3 ], x, 12 );
    U8_TO_U32_BE( s->W[  4 ], x, 16 );
    U8_TO_U32_BE( s->W[  5 ], x, 20 );
    U8_TO_U32_BE( s->W[  6 ], x, 24 );
    U8_TO_U32_BE( s->W[  7 ], x, 28 );
    U8_TO_U32_BE( s->W[  8 ], x, 32 );
    U8_TO_U32_BE( s->W[  9 ], x, 36 );
    U8_TO_U32_BE( s->W[ 10 ], x, 40 );
    U8_TO_U32_BE( s->W[ 11 ], x, 44 );
    U8_TO_U32_BE( s->W[ 12 ], x, 48 );
    U8_TO_U32_BE( s->W[ 13 ], x, 52 );
    U8_TO_U32_BE( s->W[ 14 ], x, 56 );
    U8_TO_U32_BE( s->W[ 15 ], x, 60 );
    
    for( int i = 16; i < 64; i += 1 ) {
        ctx->W[ i ] = SHA2_256_S1( ctx->W[ i -  2 ] ) + ( ctx->W[ i -  7 ] ) +
                      SHA2_256_S0( ctx->W[ i - 15 ] ) + ( ctx->W[ i - 16 ] ) ;
    }
    
    for( int i =  0; i < 64; i += 8 ) {
        SHA2_256_R( a, b, c, d, e, f, g, h, ctx->W[ i + 0 ], SHA2_256_K[ i + 0 ] );
        SHA2_256_R( h, a, b, c, d, e, f, g, ctx->W[ i + 1 ], SHA2_256_K[ i + 1 ] );
        SHA2_256_R( g, h, a, b, c, d, e, f, ctx->W[ i + 2 ], SHA2_256_K[ i + 2 ] );
        SHA2_256_R( f, g, h, a, b, c, d, e, ctx->W[ i + 3 ], SHA2_256_K[ i + 3 ] );
        SHA2_256_R( e, f, g, h, a, b, c, d, ctx->W[ i + 4 ], SHA2_256_K[ i + 4 ] );
        SHA2_256_R( d, e, f, g, h, a, b, c, ctx->W[ i + 5 ], SHA2_256_K[ i + 5 ] );
        SHA2_256_R( c, d, e, f, g, h, a, b, ctx->W[ i + 6 ], SHA2_256_K[ i + 6 ] );
        SHA2_256_R( b, c, d, e, f, g, h, a, ctx->W[ i + 7 ], SHA2_256_K[ i + 7 ] );
    }
    
    ctx->H[ 0 ] += a;
    ctx->H[ 1 ] += b;
    ctx->H[ 2 ] += c;
    ctx->H[ 3 ] += d;
    ctx->H[ 4 ] += e;
    ctx->H[ 5 ] += f;
    ctx->H[ 6 ] += g;
    ctx->H[ 7 ] += h;

	//unsigned int a, b, c, d, e, f, g, h;
	//unsigned int s0, s1;
	//unsigned int t1, t2;
	//unsigned int work_space[16];
	//unsigned int n;
	//unsigned int i;

	//a = iv[0]; b = iv[1]; c = iv[2]; d = iv[3];
	//e = iv[4]; f = iv[5]; g = iv[6]; h = iv[7];

	//for (i = 0; i < 16; ++i) {
	//	n = BigEndian(&data);
	//	t1 = work_space[i] = n;
	//	t1 += h + Sigma1(e) + Ch(e, f, g) + k256[i];
	//	t2 = Sigma0(a) + Maj(a, b, c);
	//	h = g; g = f; f = e; e = d + t1;
	//	d = c; c = b; b = a; a = t1 + t2;
	//}

	//for ( ; i < 64; ++i) {
	//	s0 = work_space[(i+1)&0x0f];
	//	s0 = sigma0(s0);
	//	s1 = work_space[(i+14)&0x0f];
	//	s1 = sigma1(s1);

	//	t1 = work_space[i&0xf] += s0 + s1 + work_space[(i+9)&0xf];
	//	t1 += h + Sigma1(e) + Ch(e, f, g) + k256[i];
	//	t2 = Sigma0(a) + Maj(a, b, c);
	//	h = g; g = f; f = e; e = d + t1;
	//	d = c; c = b; b = a; a = t1 + t2;
	//}

	//iv[0] += a; iv[1] += b; iv[2] += c; iv[3] += d;
	//iv[4] += e; iv[5] += f; iv[6] += g; iv[7] += h;
}
