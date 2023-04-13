/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

#ifndef TEEP_COSE_H
#define TEEP_COSE_H

#include "teep/teep_common.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/t_cose_sign1_sign.h"

#if defined(LIBTEEP_PSA_CRYPTO_C)
#include "psa/crypto.h"
#else
#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/opensslv.h"

#define OPENSSL_VERSION_111 0x10101000L
#define OPENSSL_VERSION_300 0x30000000L
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_300
#include "openssl/param_build.h"
#endif

#endif /* LIBTEEP_PSA_CRYPTO_C */

#define PRIME256V1_PRIVATE_KEY_LENGTH       32
#define PRIME256V1_PRIVATE_KEY_CHAR_LENGTH  64
#define PRIME256V1_PUBLIC_KEY_LENGTH        65
#define PRIME256V1_PUBLIC_KEY_CHAR_LENGTH   130
#define SECP384R1_PRIVATE_KEY_LENGTH        48
#define SECP384R1_PRIVATE_KEY_CHAR_LENGTH   96
#define SECP384R1_PUBLIC_KEY_LENGTH         97
#define SECP384R1_PUBLIC_KEY_CHAR_LENGTH    194
#define SECP521R1_PRIVATE_KEY_LENGTH        66
#define SECP521R1_PRIVATE_KEY_CHAR_LENGTH   132
#define SECP521R1_PUBLIC_KEY_LENGTH         133
#define SECP521R1_PUBLIC_KEY_CHAR_LENGTH    266

typedef struct teep_key {
    int cose_usage; // COSE_Sign1, COSE_Sign, COSE_Encrypt0, COSE_Encrypt, etc.
    const unsigned char *private_key;
    size_t private_key_len;
    const unsigned char *public_key;
    size_t public_key_len;
    int cose_algorithm_id;
    struct t_cose_key cose_key;
    UsefulBufC kid;
} teep_key_t;

typedef struct teep_mechanism {
    int cose_tag; // COSE_Sign1, COSE_Sign, COSE_Encrypt0, COSE_Encrypt, etc.
    teep_key_t key;
    bool use;
} teep_mechanism_t;

teep_err_t teep_sign_cose_sign1(const UsefulBufC raw_cbor, const teep_key_t *key_pair, UsefulBuf *returned_payload);
teep_err_t teep_verify_cose_sign1(const UsefulBufC signed_cose, const teep_key_t *public_key, UsefulBufC *returned_payload);

/*!
    \brief  Create ES256 key pair

    \param[in]  private_key         Pointer of char array type of private key.
    \param[in]  public_key          Pointer of char array type of public key.
    \param[in]  kid                 kid to be encoded in unprotected header or `NULLUsefulBufC`.
    \param[out] cose_public_key     Pointer of teep_key_t type of public key.

    \return     This returns SUIT_SUCCESS or SUIT_ERR_FATAL.

    The length of the char array public key is estimated from the algorithm and library.
 */
teep_err_t teep_key_init_es256_key_pair(const unsigned char *private_key,
                                        const unsigned char *public_key,
                                        UsefulBufC kid,
                                        teep_key_t *cose_key_pair);

/*!
    \brief  Create ES256 public key

    \param[in]  public_key          Pointer of char array type of public key.
    \param[in]  kid                 kid to be encoded in unprotected header or `NULLUsefulBufC`.
    \param[out] cose_public_key     Pointer of teep_key_t type of public key.

    \return     This returns SUIT_SUCCESS or SUIT_ERR_FAILED_TO_VERIFY.

    The length of the char array public key is estimated from the algorithm and library.
 */
teep_err_t teep_key_init_es256_public_key(const unsigned char *public_key,
                                          UsefulBufC kid,
                                          teep_key_t *cose_key_pair);

/*!
    \brief  Create ES384 key pair

    \param[in]  private_key         Pointer of char array type of private key.
    \param[in]  public_key          Pointer of char array type of public key.
    \param[in]  kid                 kid to be encoded in unprotected header or `NULLUsefulBufC`.
    \param[out] cose_public_key     Pointer of teep_key_t type of public key.

    \return     This returns SUIT_SUCCESS or SUIT_ERR_FATAL.

    The length of the char array public key is estimated from the algorithm and library.
 */
teep_err_t teep_key_init_es384_key_pair(const unsigned char *private_key,
                                        const unsigned char *public_key,
                                        UsefulBufC kid,
                                        teep_key_t *cose_key_pair);

/*!
    \brief  Create ES384 public key

    \param[in]  public_key          Pointer of char array type of public key.
    \param[in]  kid                 kid to be encoded in unprotected header or `NULLUsefulBufC`.
    \param[out] cose_public_key     Pointer of teep_key_t type of public key.

    \return     This returns SUIT_SUCCESS or SUIT_ERR_FAILED_TO_VERIFY.

    The length of the char array public key is estimated from the algorithm and library.
 */
teep_err_t teep_key_init_es384_public_key(const unsigned char *public_key,
                                          UsefulBufC kid,
                                          teep_key_t *cose_key_pair);

/*!
    \brief  Create ES521 key pair

    \param[in]  private_key         Pointer of char array type of private key.
    \param[in]  public_key          Pointer of char array type of public key.
    \param[in]  kid                 kid to be encoded in unprotected header or `NULLUsefulBufC`.
    \param[out] cose_public_key     Pointer of teep_key_t type of public key.

    \return     This returns SUIT_SUCCESS or SUIT_ERR_FATAL.

    The length of the char array public key is estimated from the algorithm and library.
 */
teep_err_t teep_key_init_es521_key_pair(const unsigned char *private_key,
                                        const unsigned char *public_key,
                                        UsefulBufC kid,
                                        teep_key_t *cose_key_pair);

/*!
    \brief  Create ES521 public key

    \param[in]  public_key          Pointer of char array type of public key.
    \param[in]  kid                 kid to be encoded in unprotected header or `NULLUsefulBufC`.
    \param[out] cose_public_key     Pointer of teep_key_t type of public key.

    \return     This returns SUIT_SUCCESS or SUIT_ERR_FAILED_TO_VERIFY.

    The length of the char array public key is estimated from the algorithm and library.
 */
teep_err_t teep_key_init_es521_public_key(const unsigned char *public_key,
                                          UsefulBufC kid,
                                          teep_key_t *cose_key_pair);

teep_err_t teep_free_key(const teep_key_t *key);

#endif  /* TEEP_COSE_H */
