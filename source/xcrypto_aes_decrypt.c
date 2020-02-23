/* aes_decrypt.c - TinyCrypt implementation of AES decryption procedure */

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
#include <tinycrypt/constants.h>
#include <tinycrypt/utils.h>

int tc_aes128_set_decrypt_key(TCAesKeySched_t s, const uint8_t *k)
{
	if (s == (TCAesKeySched_t) 0) {
		return TC_CRYPTO_FAIL;
	} else if (k == (const uint8_t *) 0) {
		return TC_CRYPTO_FAIL;
	}

    tc_aes128_set_encrypt_key(s, k);

    int32_t *w = (int32_t *) s;

    for (int i = 1; i < Nr; i++) {
        int j = i * 4;

        w[j]     = aes_mix_inv(w[j]);
        w[j + 1] = aes_mix_inv(w[j + 1]);
        w[j + 2] = aes_mix_inv(w[j + 2]);
        w[j + 3] = aes_mix_inv(w[j + 3]);
    }

    return TC_CRYPTO_SUCCESS;
}

int tc_aes_decrypt(uint8_t *out, const uint8_t *in, const TCAesKeySched_t s)
{
    aes_dec(out, in, s->words);

	return TC_CRYPTO_SUCCESS;
}
