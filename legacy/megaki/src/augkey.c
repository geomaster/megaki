/* crypto/rsa/rsa_aug_key.c  -*- Mode: C; c-file-style: "eay" -*- */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */
#include "augkey.h"
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

/*
 * If key has d, e and n, but not p, q, dmp1, dmq1 and iqmp, try
 * to calculate these extra factors.  Return 1 on success or 0
 * on failure.  (The key may still be useable even if this fails.)
 */
int RSA_augment_key(RSA *key)
{
    int      spotted;
    BN_CTX  *ctx;
    BIGNUM  *ktot;
    BIGNUM  *t;
    BIGNUM  *tmp;
    BIGNUM  *a;
    BIGNUM  *two;
    BIGNUM  *l00;
    BIGNUM  *cand;
    BIGNUM  *k;
    BIGNUM  *n_1;

    if (!key || !key->d || !key->e || !key->n) return 0;

    spotted = 0;

    ctx    = BN_CTX_new( );
    ktot   = BN_new( );
    t      = BN_new( );
    tmp    = BN_new( );
    a      = 0; BN_dec2bn( &a,   "2" );
    two    = 0; BN_dec2bn( &two, "2" );
    l00    = 0; BN_dec2bn( &l00, "100" );
    cand   = BN_new( );
    k      = BN_new( );
    n_1    = BN_new( ); if (!BN_sub( n_1, key->n, BN_value_one( ) )) goto fail;

/* Python-code comments from PyCrypto
// ------------------------------------------------------------------
//      # Compute factors p and q from the private exponent d.
//      # We assume that n has no more than two factors.
//      # See 8.2.2(i) in Handbook of Applied Cryptography.
//      ktot = d*e-1*/

    if (!BN_mul( tmp, key->d, key->e, ctx ))    goto fail;
    if (!BN_sub( ktot, tmp, BN_value_one( ) ))  goto fail;

/*      # The quantity d*e-1 is a multiple of phi(n), even,
//      # and can be represented as t*2^s.
//      t = ktot */

    if (!BN_copy( t, ktot ))                    goto fail;

/*      while t%2==0:
//          t=divmod(t,2)[0] */

    while (!BN_is_odd( t ))
        if (!BN_rshift1( t, t ))                goto fail;

/*      # Cycle through all multiplicative inverses in Zn.
//      # The algorithm is non-deterministic, but there is a 50% chance
//      # any candidate a leads to successful factoring.
//      # See "Digitalized Signatures and Public Key Functions as Intractable
//      # as Factorization", M. Rabin, 1979
//      spotted = 0
//      a = 2

//      while not spotted and a<100: */
    while (!spotted && BN_cmp( a, l00 ) < 0) {

/*          k = t */
        if (!BN_copy( k, t ))                   goto fail;

/*          # Cycle through all values a^{t*2^i}=a^k
//          while k<ktot: */
        while (BN_cmp( k, ktot ) < 0) {

/*              cand = pow(a,k,n) */
            if (!BN_mod_exp( cand, a, k, key->n, ctx ))         goto fail;

/*              # Check if a^k is a non-trivial root of unity (mod n)
//              if cand!=1 and cand!=(n-1) and pow(cand,2,n)==1: */
            if (BN_cmp( cand, BN_value_one( ) ) && BN_cmp( cand, n_1 )) {
                if (!BN_mod_exp( tmp, cand, two, key->n, ctx )) goto fail;
                if (BN_cmp( tmp, BN_value_one( )) == 0) {
/*                  # We have found a number such that (cand-1)(cand+1)=0 (mod n).
//                  # Either of the terms divides n.
//                  obj.p = GCD(cand+1,n)
//                  spotted = 1
//                  break */
                    key->p = BN_new( );
                    if (!BN_add( tmp, cand, BN_value_one( ) ))  goto fail;
                    if (!BN_gcd( key->p, tmp, key->n, ctx ))    goto fail;
                    spotted = 1;
                    break;
                }
            }

//              k = k*2
            if (!BN_lshift1( k, k ))          goto fail;
        }

/*          # This value was not any good... let's try another!
//          a = a+2 */
        if (!BN_add( a, a, two ))               goto fail;
    }

    if (!spotted) {
        /* Unable to compute factors P and Q from exponent D */
        goto fail;
    }

    key->q = BN_new( );
    if (!BN_div( key->q, tmp, key->n, key->p, ctx ))    goto fail;
    if (!BN_is_zero( tmp )) {
        /* Curses!  Tricked with a bogus P! */
        goto fail;
    }

    key->dmp1 = BN_new( );
    key->dmq1 = BN_new( );
    key->iqmp = BN_new( );

    if (!BN_sub( tmp, key->p, BN_value_one( ) ))            goto fail;
    if (!BN_mod( key->dmp1, key->d, tmp, ctx ))             goto fail;
    if (!BN_sub( tmp, key->q, BN_value_one( ) ))            goto fail;
    if (!BN_mod( key->dmq1, key->d, tmp, ctx ))             goto fail;
    if (!BN_mod_inverse( key->iqmp, key->q, key->p, ctx ))  goto fail;

    if (RSA_check_key( key ) == 1)                          goto cleanup;

  fail:
    BN_free( key->p );     key->p = 0;
    BN_free( key->q );     key->q = 0;
    BN_free( key->dmp1 );  key->dmp1 = 0;
    BN_free( key->dmq1 );  key->dmq1 = 0;
    BN_free( key->iqmp );  key->iqmp = 0;
    spotted = 0;

  cleanup:
    BN_free( k );
    BN_free( cand );

    BN_free( n_1 );
    BN_free( l00 );
    BN_free( two );

    BN_free( a );

    BN_free( tmp );
    BN_free( t );
    BN_free( ktot );

    BN_CTX_free( ctx );

    return spotted;
}
