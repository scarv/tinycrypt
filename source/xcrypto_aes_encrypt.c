/* aes_encrypt.c - TinyCrypt implementation of AES encryption procedure */

/*
 *  Copyright (C) 2017 by Intel Corporation, All Rights Reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *    - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *    - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *    - Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include <tinycrypt/aes.h>
#include <tinycrypt/utils.h>
#include <tinycrypt/constants.h>

static inline unsigned int rotword(unsigned int a)
{
	return (((a) >> 24)|((a) << 8));
}

void aes_enc_exp_step( uint8_t* r, const uint8_t* rk, uint8_t rcon ) {
    r[0] = rcon ^ aes_sub(rk[13]) ^ rk[0];
    r[1] =        aes_sub(rk[14]) ^ rk[1];
    r[2] =        aes_sub(rk[15]) ^ rk[2];
    r[3] =        aes_sub(rk[12]) ^ rk[3];
    
    r[4] =        r[0] ^ rk[4];
    r[5] =        r[1] ^ rk[5];
    r[6] =        r[2] ^ rk[6];
    r[7] =        r[3] ^ rk[7];
    
    r[8] =        r[4] ^ rk[8];
    r[9] =        r[5] ^ rk[9];
    r[10] =        r[6] ^ rk[10];
    r[11] =        r[7] ^ rk[11];
    
    r[12] =        r[8] ^ rk[12];
    r[13] =        r[9] ^ rk[13];
    r[14] =        r[10] ^ rk[14];
    r[15] =        r[11] ^ rk[15];
}

#define U8_TO_U8_N(r,x) { \
    (r)[  0 ] = (x)[  0 ]; (r)[  1 ] = (x)[  1 ]; (r)[  2 ] = (x)[  2 ]; (r)[  3 ] = (x)[  3 ]; \
    (r)[  4 ] = (x)[  4 ]; (r)[  5 ] = (x)[  5 ]; (r)[  6 ] = (x)[  6 ]; (r)[  7 ] = (x)[  7 ]; \
    (r)[  8 ] = (x)[  8 ]; (r)[  9 ] = (x)[  9 ]; (r)[ 10 ] = (x)[ 10 ]; (r)[ 11 ] = (x)[ 11 ]; \
    (r)[ 12 ] = (x)[ 12 ]; (r)[ 13 ] = (x)[ 13 ]; (r)[ 14 ] = (x)[ 14 ]; (r)[ 15 ] = (x)[ 15 ]; \
}

#define U8_TO_U8_T(r,x) { \
    (r)[  0 ] = (x)[  0 ]; (r)[  1 ] = (x)[  4 ]; (r)[  2 ] = (x)[  8 ]; (r)[  3 ] = (x)[ 12 ]; \
    (r)[  4 ] = (x)[  1 ]; (r)[  5 ] = (x)[  5 ]; (r)[  6 ] = (x)[  9 ]; (r)[  7 ] = (x)[ 13 ]; \
    (r)[  8 ] = (x)[  2 ]; (r)[  9 ] = (x)[  6 ]; (r)[ 10 ] = (x)[ 10 ]; (r)[ 11 ] = (x)[ 14 ]; \
    (r)[ 12 ] = (x)[  3 ]; (r)[ 13 ] = (x)[  7 ]; (r)[ 14 ] = (x)[ 11 ]; (r)[ 15 ] = (x)[ 15 ]; \
}

int tc_aes128_set_encrypt_key(TCAesKeySched_t s, const uint8_t* k) {
    uint8_t rcp[11] = {
        0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36
    };
    uint8_t*  rp = s->words;

	if (s == (TCAesKeySched_t) 0) {
		return TC_CRYPTO_FAIL;
	} else if (k == (const uint8_t *) 0) {
		return TC_CRYPTO_FAIL;
	}
    
    U8_TO_U8_N(rp, k);
    
    for (int i = 1; i < Nr + 1; i++) {
        aes_enc_exp_step(rp + (4 * Nb), rp, rcp[i]);

        rp += (4 * Nb);
    }

    return TC_CRYPTO_SUCCESS;
}

int tc_aes_encrypt(uint8_t *out, const uint8_t *in, const TCAesKeySched_t s)
{
    aes_enc(out, in, s->words);

	return TC_CRYPTO_SUCCESS;
}
