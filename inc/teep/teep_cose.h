/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

#ifndef TEEP_COSE_H
#define TEEP_COSE_H

#include "teep/teep_common.h"
#include "qcbor/qcbor_decode.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/t_cose_sign1_sign.h"

/* for EdDSA aux buffer */
#ifndef TEEP_AUXILIARY_BUFFER_SIZE
  #define TEEP_AUXILIARY_BUFFER_SIZE            100
#endif

#if defined(LIBTEEP_PSA_CRYPTO_C)
  #if !defined(SHA256_DIGEST_LENGTH)
  #define SHA256_DIGEST_LENGTH 32
  #endif
#include "psa/crypto.h"
#else
#include "openssl/sha.h"
#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/opensslv.h"

#define OPENSSL_VERSION_111 0x10101000L
#define OPENSSL_VERSION_300 0x30000000L
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_300
#include "openssl/core_names.h"
#include "openssl/param_build.h"
#endif

#endif /* LIBTEEP_PSA_CRYPTO_C */

#define TEEP_COSE_KTY                   (1)
#define TEEP_COSE_KTY_OKP               (1)
#define TEEP_COSE_KTY_EC2               (2)
#define TEEP_COSE_KTY_SYMMETRIC         (4)

#define TEEP_COSE_CRV                   (-1)
#define TEEP_COSE_CRV_P256              (1)
#define TEEP_COSE_CRV_P384              (2)
#define TEEP_COSE_CRV_P521              (3)
#define TEEP_COSE_CRV_X25519            (4)
#define TEEP_COSE_CRV_X448              (5)
#define TEEP_COSE_CRV_ED25519           (6)
#define TEEP_COSE_CRV_ED448             (7)
#define TEEP_COSE_X                     (-2)
#define TEEP_COSE_Y                     (-3)
#define TEEP_COSE_D                     (-4)
#define TEEP_COSE_K                     (-1)

#define PRIME256V1_PRIVATE_KEY_LENGTH       32
#define PRIME256V1_PUBLIC_KEY_LENGTH        65
#define SECP384R1_PRIVATE_KEY_LENGTH        48
#define SECP384R1_PUBLIC_KEY_LENGTH         97
#define SECP521R1_PRIVATE_KEY_LENGTH        66
#define SECP521R1_PUBLIC_KEY_LENGTH         133
#define ED25519_PRIVATE_KEY_LENGTH          32
#define ED25519_PUBLIC_KEY_LENGTH           32
#define ED448_PRIVATE_KEY_LENGTH            57
#define ED448_PUBLIC_KEY_LENGTH             57

#define TEEP_MAX_PRIVATE_KEY_LEN            SECP521R1_PRIVATE_KEY_LENGTH
#define TEEP_MAX_PUBLIC_KEY_LEN             SECP521R1_PUBLIC_KEY_LENGTH

typedef struct teep_key {
    int cose_usage; // COSE_Sign1, COSE_Sign, COSE_Encrypt0, COSE_Encrypt, etc.
    const unsigned char *private_key;
    size_t private_key_len;
    const unsigned char *public_key;
    size_t public_key_len;
    int cose_algorithm_id;
    struct t_cose_key cose_key;
    UsefulBufC kid;
    union {
        struct t_cose_signature_sign_main signer_ecdsa;
        struct t_cose_signature_sign_eddsa signer_eddsa;
        struct t_cose_signature_verify_main verifier_ecdsa;
        struct t_cose_signature_verify_eddsa verifier_eddsa;
    };
} teep_key_t;

typedef struct teep_mechanism {
    int cose_tag; // COSE_Sign1, COSE_Sign, COSE_Encrypt0, COSE_Encrypt, etc.
    teep_key_t key;
    bool use;
} teep_mechanism_t;

teep_err_t teep_sign_cose_sign1(const UsefulBufC raw_cbor,
                                const teep_mechanism_t *mechanism,
                                UsefulBuf *returned_payload);
teep_err_t teep_sign_cose_sign(const UsefulBufC raw_cbor,
                               const teep_mechanism_t mechanisms[],
                               const size_t num_mechanism,
                               UsefulBuf *returned_payload);
teep_err_t teep_verify_cose_sign1(const UsefulBufC signed_cose,
                                  const teep_mechanism_t *mechanism,
                                  UsefulBufC *returned_payload);
teep_err_t teep_verify_cose_sign(const UsefulBufC signed_cose,
                                 const teep_mechanism_t mechanisms[],
                                 const size_t num_mechanism,
                                 UsefulBufC *returned_payload);

/*!
    \brief  Create ES256 key pair

    \param[in]  private_key         Pointer of char array type of private key.
    \param[in]  public_key          Pointer of char array type of public key.
    \param[in]  kid                 kid to be encoded in unprotected header or `NULLUsefulBufC`.
    \param[out] cose_public_key     Pointer of teep_key_t type of public key.

    \return     This returns TEEP_SUCCESS or TEEP_ERR_FATAL.

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

    \return     This returns TEEP_SUCCESS or TEEP_ERR_FAILED_TO_VERIFY.

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

    \return     This returns TEEP_SUCCESS or TEEP_ERR_FATAL.

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

    \return     This returns TEEP_SUCCESS or TEEP_ERR_FAILED_TO_VERIFY.

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

    \return     This returns TEEP_SUCCESS or TEEP_ERR_FATAL.

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

    \return     This returns TEEP_SUCCESS or TEEP_ERR_FAILED_TO_VERIFY.

    The length of the char array public key is estimated from the algorithm and library.
 */
teep_err_t teep_key_init_es521_public_key(const unsigned char *public_key,
                                          UsefulBufC kid,
                                          teep_key_t *cose_key_pair);

teep_err_t teep_free_key(const teep_key_t *key);
teep_err_t teep_set_mechanism_from_cose_key_from_item(QCBORDecodeContext *context,
                                                      QCBORItem *item,
                                                      UsefulBufC kid,
                                                      teep_mechanism_t *mechanism);
teep_err_t teep_set_mechanism_from_cose_key(UsefulBufC buf,
                                            UsefulBufC kid,
                                            teep_mechanism_t *mechanism);
/*!
    \brief  Calculate COSE_Key thumbprint

    \param[in]  cose_key            Pointer of the COSE_Key buffer.
    \param[out] thumbprint          Pointer and length to the output buffer.

    \return     This returns TEEP_SUCCESS or TEEP_ERR_FATAL.

    The length of the thumbprint MUST be SHA256_DIGEST_LENGTH = 32.
 */
teep_err_t teep_calc_cose_key_thumbprint(UsefulBufC cose_key,
                                         UsefulBuf thumbprint);

#endif  /* TEEP_COSE_H */
