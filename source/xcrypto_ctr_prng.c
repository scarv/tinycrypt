/* ctr_prng.c - TinyCrypt implementation of CTR-PRNG */

/*
 * Copyright (c) 2016, Chris Morrison
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tinycrypt/ctr_prng.h>
#include <tinycrypt/utils.h>
#include <tinycrypt/constants.h>
#include <string.h>

static inline uint32_t _xc_rngtest() {
    uint32_t rd;

    __asm__("xc.rngtest %0" : "=r"(rd));

    return rd;
}

static inline void _xc_rngseed(uint32_t rs1) {
    __asm__("xc.rngseed %0" : "=r"(rs1));
}

static inline uint32_t _xc_rngsamp() {
    uint32_t rd;

    __asm__("xc.rngsamp %0" : "=r"(rd));

    return rd;
}

/**
 *  @brief CTR PRNG update
 *  Updates the internal state of supplied the CTR PRNG context
 *  increments it by one
 *  @return none
 *  @note Assumes: providedData is (TC_AES_KEY_SIZE + TC_AES_BLOCK_SIZE) bytes long
 *  @param ctx IN/OUT -- CTR PRNG state
 *  @param providedData IN -- data used when updating the internal state
 */
static void tc_ctr_prng_update(TCCtrPrng_t * const ctx, uint8_t const * const providedData)
{

    for (int i = 0; i < (TC_AES_KEY_SIZE + TC_AES_BLOCK_SIZE); i += 1) {
        _xc_rngseed(providedData[i]);
    }
}

int tc_ctr_prng_init(TCCtrPrng_t * const ctx, 
		     uint8_t const * const entropy,
		     unsigned int entropyLen, 
		     uint8_t const * const personalization,
		     unsigned int pLen)
{
    for (int i = 0; i < entropyLen; i += 1) {
        _xc_rngseed(entropy[i]);
    }

    for (int i = 0; i < pLen; i += 1) {
        _xc_rngseed(personalization[i]);
    }

    return _xc_rngtest();
}

int tc_ctr_prng_reseed(TCCtrPrng_t * const ctx, 
			uint8_t const * const entropy,
			unsigned int entropyLen,
			uint8_t const * const additional_input,
			unsigned int additionallen)
{
    return tc_ctr_prng_init(
        ctx, entropy, entropyLen, additional_input, additionallen
    );
}

int tc_ctr_prng_generate(TCCtrPrng_t * const ctx,
			uint8_t const * const additional_input,
			unsigned int additionallen,
			uint8_t * const out,
			unsigned int outlen)
{

    for (int i = 0; i < additionallen; i += 1) {
        _xc_rngseed(additional_input[i]);
    }

    for (int i = 0; i < outlen; i += 1) {
        int is_valid = _xc_rngtest();

        if (!is_valid) {
            return TC_CRYPTO_FAIL;
        }

        out[i] = _xc_rngsamp();
    }

    return TC_CRYPTO_SUCCESS;
}

void tc_ctr_prng_uninstantiate(TCCtrPrng_t * const ctx)
{
    // NOT IMPLEMENTED
}
