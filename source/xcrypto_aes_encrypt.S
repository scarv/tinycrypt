// Copyright (C) 2019 SCARV project <info@scarv.org>
//
// Use of this source code is restricted per the MIT license, a copy of which
// can be found at https://opensource.org/licenses/MIT (or should be included
// as LICENSE.txt within the associated archive or repository).

.macro AES_LDM M0 M1 M2 M3 ADDR
  lw \M0, 0x0(\ADDR)
  lw \M1, 0x4(\ADDR)
  lw \M2, 0x8(\ADDR)
  lw \M3, 0xC(\ADDR)
.endm

.macro AES_STM M0 M1 M2 M3 ADDR
  sw \M0, 0x0(\ADDR)
  sw \M1, 0x4(\ADDR)
  sw \M2, 0x8(\ADDR)
  sw \M3, 0xC(\ADDR)
.endm

.macro AES_ENC_RND_KEY S0 S1 S2 S3 K0 K1 K2 K3
  xor  \S0, \S0, \K0
  xor  \S1, \S1, \K1
  xor  \S2, \S2, \K2
  xor  \S3, \S3, \K3
.endm

.macro AES_DEC_RND_KEY S0 S1 S2 S3 K0 K1 K2 K3
  xor  \S0, \S0, \K0
  xor  \S1, \S1, \K1
  xor  \S2, \S2, \K2
  xor  \S3, \S3, \K3
.endm
	
// ============================================================================	

.section .text

.func    aes_enc
.global  aes_enc

// void aes_enc( uint8_t* r, uint8_t* m, uint8_t* k );
//
// a0 =  uint8_t* r
// a1 =  uint8_t* m
// a2 =  uint8_t* k
//
// a6 = i
	
aes_enc: AES_LDM         t0, t1, t2, t3, a1


         AES_LDM         t4, t5, t6, a7, a2
         AES_ENC_RND_KEY t0, t1, t2, t3, t4, t5, t6, a7

         li a6, 9

.l0:     xc.aessub.enc   t4, t0, t1
         xc.aessub.enc   t5, t2, t3
         xc.aessub.enc   t6, t1, t2
         xc.aessub.enc   a7, t3, t0

         xc.aesmix.enc   t0, t4, t5
         xc.aesmix.enc   t1, t6, a7
         xc.aesmix.enc   t2, t5, t4
         xc.aesmix.enc   t3, a7, t6

         addi a2, a2,  16
         AES_LDM         t4, t5, t6, a7, a2
         AES_ENC_RND_KEY t0, t1, t2, t3, t4, t5, t6, a7

         addi a6, a6, -1
         bgtz a6, .l0

         li     a3, 0x0000FFFF
         li     a4, 0xFFFF0000

         xc.aessub.enc   t4, t2, t3
         xc.aessub.enc   t5, t3, t0
         xc.aessub.enc   t6, t0, t1
         xc.aessub.enc   a7, t1, t2

         and    a5, t6, a3          // a5 =  X, X, 0, 5
         and    a6, t4, a4          // a6 = 15,10, X, X
         or     t0, a5, a6          // t0 = 15,10, 0, 5

         and    a5, a7, a3          // a5 =  X, X, 4, 9
         and    a6, t5, a4          // a6 =  3,14, X, X
         or     t1, a5, a6

         and    a5, t4, a3          // a5 =  X, X, 8, 3
         and    a6, t6, a4          // a6 =  7, 2, X, X
         or     t2, a5, a6

         and    a5, t5, a3          // a5 =  X, X,12, 1
         and    a6, a7, a4          // a6 = 11, 6, X, X
         or     t3, a5, a6

         addi a2, a2,  16
         AES_LDM         t4, t5, t6, a7, a2
         AES_ENC_RND_KEY t0, t1, t2, t3, t4, t5, t6, a7

         AES_STM         t0, t1, t2, t3, a0

         ret

.endfunc
