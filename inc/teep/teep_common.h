/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef TEEP_COMMON_H
#define TEEP_COMMON_H

#include "qcbor/qcbor.h"
#include "qcbor/qcbor_spiffy_decode.h"

// Function results
typedef enum teep_err {
    TEEP_SUCCESS = 0,
    TEEP_ERR_INVALID_TYPE_OF_VALUE,
    TEEP_ERR_INVALID_VALUE,
    TEEP_ERR_INVALID_TYPE_OF_KEY,
    TEEP_ERR_INVALID_KEY,
    TEEP_ERR_INVALID_LENGTH,
    TEEP_ERR_INVALID_MESSAGE_TYPE,

    TEEP_ERR_ENCODING_FAILED,
    TEEP_ERR_DECODING_FAILED,

    TEEP_ERR_CBOR_WITHOUT_COSE,
    TEEP_ERR_VERIFICATION_FAILED,
    TEEP_ERR_SIGNING_FAILED,

    TEEP_ERR_NOT_IMPLEMENTED,
    TEEP_ERR_NO_SUPPORTED_VERSION,
    TEEP_ERR_NO_SUPPORTED_CIPHERSUITE,

    TEEP_ERR_NO_MEMORY,
    TEEP_ERR_ON_HTTP_POST,

    TEEP_ERR_UNEXPECTED_ERROR,
    TEEP_ERR_ABORT,
    TEEP_ERR_FATAL,
} teep_err_t;

typedef struct teep_buf {
    size_t          len;
    const uint8_t   *ptr;
} teep_buf_t;

teep_err_t teep_print_hex_within_max(const uint8_t *array, const size_t size, const size_t size_max);
teep_err_t teep_print_hex_string(const uint8_t *array, const int size);
teep_err_t teep_print_hex(const uint8_t *array, size_t size);
teep_err_t teep_print_text(const char *text, size_t size);
teep_err_t teep_print_string(const teep_buf_t *string);
void teep_print_error_string(const char *message);
void teep_print_debug_string(const char *message);
void teep_print_debug_string_uint32(const char *message, uint32_t value);
void teep_debug_print(QCBORDecodeContext *message,
                      QCBORItem *item,
                      QCBORError *error,
                      const char *func_name,
                      uint8_t expecting);

struct teep_cipher_suite;
bool teep_cipher_suite_is_same(struct teep_cipher_suite a, struct teep_cipher_suite b);
uint32_t teep_array_to_int32(const uint8_t *array, int32_t byte_count);
uint64_t teep_array_to_int64(const uint8_t *array);
bool teep_is_valid_mechanism(int64_t cose_mechanism_key);

#endif  // TEEP_COMMON_H
