/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

#ifndef TEEP_EXAMPLES_COMMON_H
#define TEEP_EXAMPLES_COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "teep/teep_cose.h"
#include "t_cose/t_cose_sign1_verify.h"

size_t read_from_file(const char *file_path, const size_t buf_len, uint8_t *buf);
size_t write_to_file(const char *file_path, const size_t buf_len, const void *buf);

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
#endif  /* TEEP_EXAMPLES_COMMON_H */
