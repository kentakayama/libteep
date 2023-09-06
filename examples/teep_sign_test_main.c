/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include "teep/teep_message_data.h"
#include "teep/teep_message_print.h"
#include "teep/teep_cose.h"
#include "teep_examples_common.h"

#define MAX_FILE_BUFFER_SIZE    16777216

#if MAX_FILE_BUFFER_SIZE > (2 * 1024)
#include <stdlib.h>
#endif

#include "teep_agent_es256_private_key.h"
#include "teep_agent_es256_public_key.h"
const unsigned char *teep_private_key = teep_agent_es256_private_key;
const unsigned char *teep_public_key = teep_agent_es256_public_key;

int main(int argc, const char * argv[])
{
    int32_t result;

    // Check arguments.
    if (argc < 1) {
        printf("%s <COSE Output File>\n", argv[0]);
        return EXIT_FAILURE;
    }

    UsefulBuf_MAKE_STACK_UB(cbor_buf, 256);
    UsefulBuf_MAKE_STACK_UB(cose_buf, 256);
    UsefulBuf_MAKE_STACK_UB(cose_one_step_buf, 256);

    uint8_t token[] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7};

    teep_success_t teep_message;
    teep_message.type = TEEP_TYPE_TEEP_SUCCESS;
    teep_message.contains = TEEP_MESSAGE_CONTAINS_TOKEN;
    teep_message.token = (teep_buf_t){.ptr = token, .len = sizeof(token)};

    uint8_t expected_success[] = {0x82, 0x05, 0xa1, 0x14, 0x48, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7};
    result = teep_encode_message((teep_message_t *)&teep_message, &cbor_buf.ptr, &cbor_buf.len);
    if (result != TEEP_SUCCESS) {
        return EXIT_FAILURE;
    }
    if (memcmp(expected_success, cbor_buf.ptr, cbor_buf.len) != 0) {
        return EXIT_FAILURE;
    }
    teep_print_hex(cbor_buf.ptr, cbor_buf.len);
    printf("\n\n");

    teep_mechanism_t mechanism;
    result = teep_key_init_es256_key_pair(teep_agent_es256_private_key, teep_agent_es256_public_key, NULLUsefulBufC, &mechanism.key);
    if (result != TEEP_SUCCESS) {
        return EXIT_FAILURE;
    }
    mechanism.cose_tag = CBOR_TAG_COSE_SIGN1;

    result = teep_sign_cose_sign1(UsefulBuf_Const(cbor_buf), &mechanism, &cose_buf);
    if (result != TEEP_SUCCESS) {
        return EXIT_FAILURE;
    }
    teep_print_hex(cose_buf.ptr, cose_buf.len);
    printf("\n\n");

    result = teep_encode_signed_message((teep_message_t *)&teep_message, &mechanism.key, &cose_one_step_buf.ptr, &cose_one_step_buf.len);
    if (result != TEEP_SUCCESS) {
        return EXIT_FAILURE;
    }
    teep_print_hex(cose_one_step_buf.ptr, cose_one_step_buf.len);
    printf("\n\n");

    if (memcmp(cose_buf.ptr, cose_one_step_buf.ptr, cose_buf.len - 64) != 0) {
        return EXIT_FAILURE;
    }

    teep_free_key(&mechanism.key);

    return EXIT_SUCCESS;
}
