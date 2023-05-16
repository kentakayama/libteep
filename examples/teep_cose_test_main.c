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

#if TEEP_ACTOR_AGENT == 1
#include "teep_agent_es256_cose_key_private.h"
UsefulBufC teep_private_key = teep_agent_es256_cose_key_private;
UsefulBufC kid = (UsefulBufC){
    .ptr = "101",
    .len = 3,
};
#elif TEEP_ACTOR_TAM == 1
#include "tam_es256_cose_key_private.h"
UsefulBufC teep_private_key = tam_es256_cose_key_private;
UsefulBufC kid = (UsefulBufC){
    .ptr = "201",
    .len = 3,
};
#elif TEEP_ACTOR_VERIFIER == 1
#include "verifier_es256_cose_key_private.h"
UsefulBufC teep_private_key = verifier_es256_cose_key_private;
UsefulBufC kid = (UsefulBufC){
    .ptr = "301",
    .len = 3,
};
#elif TEEP_ACTOR_TRUST_ANCHOR == 1
#include "trust_anchor_prime256v1_cose_key_private.h"
UsefulBufC teep_private_key = trust_anchor_prime256v1_cose_key_private;
UsefulBufC kid = NULLUsefulBufC;
#else
#error Signing key is not specified
#endif

int main(int argc, const char * argv[]) {
    int32_t result;

    // Check arguments.
    if (argc < 2) {
        printf("%s <CBOR Input File> [<COSE Output File>]\n", argv[0]);
        return EXIT_FAILURE;
    }

    teep_mechanism_t mechanism;
    result = teep_set_mechanism_from_cose_key(teep_private_key, kid, &mechanism);
    if (result != TEEP_SUCCESS) {
        printf("main : Failed to create key pair. %s(%d)\n", teep_err_to_str(result), result);
        return EXIT_FAILURE;
    }
    mechanism.cose_tag = CBOR_TAG_COSE_SIGN1;
    mechanism.use = true;

    // Read cbor file.
    printf("main : Read CBOR file.\n");
#if MAX_FILE_BUFFER_SIZE > (2 * 1024)
    UsefulBuf cbor_buf;
    cbor_buf.ptr = malloc(MAX_FILE_BUFFER_SIZE);
    cbor_buf.len = MAX_FILE_BUFFER_SIZE;
#else
    UsefulBuf_MAKE_STACK_UB(cbor_buf, MAX_FILE_BUFFER_SIZE);
#endif
    cbor_buf.len = read_from_file(argv[1], cbor_buf.ptr, MAX_FILE_BUFFER_SIZE);
    if (!cbor_buf.len) {
        printf("main : Failed to read CBOR file \"%s\".\n", argv[2]);
        return EXIT_FAILURE;
    }
    teep_print_hex_within_max(cbor_buf.ptr, cbor_buf.len, cbor_buf.len);
    printf("\n");

    // Create cose signed file.
    printf("main : Create signed cose file.\n");
#if MAX_FILE_BUFFER_SIZE > (2 * 1024)
    UsefulBuf signed_cose;
    signed_cose.ptr = malloc(MAX_FILE_BUFFER_SIZE);
    signed_cose.len = MAX_FILE_BUFFER_SIZE;
#else
    UsefulBuf_MAKE_STACK_UB(signed_cose, MAX_FILE_BUFFER_SIZE);
#endif
    result = teep_sign_cose_sign1(UsefulBuf_Const(cbor_buf), &mechanism.key, &signed_cose);
    if (result != TEEP_SUCCESS) {
        printf("main : Failed to sign. %s(%d)\n", teep_err_to_str(result), result);
        return EXIT_FAILURE;
    }

    teep_print_hex_within_max(signed_cose.ptr, signed_cose.len, signed_cose.len);
    printf("\n");

    // Verify cose signed file.
    UsefulBufC returned_payload;
    result = teep_verify_cose_sign1(UsefulBuf_Const(signed_cose), &mechanism.key, &returned_payload);
    if (result != TEEP_SUCCESS) {
        printf("Failed to verify file. %s(%d)\n", teep_err_to_str(result), result);
        return EXIT_FAILURE;
    }
    printf("main : Succeed to verify. Print cose payload.\n");
    teep_print_hex(returned_payload.ptr, returned_payload.len);
    printf("\n");

    if (argc > 2) {
        size_t write_len = write_to_file(argv[2], signed_cose.ptr, signed_cose.len);
        if (!write_len) {
            printf("main : Failed to write COSE signed CBOR to \"%s\".\n", argv[2]);
            return EXIT_FAILURE;
        }
        printf("main : Succeed to write to \"%s\".\n", argv[2]);
    }

    teep_free_key(&mechanism.key);

#if MAX_FILE_BUFFER_SIZE > (2 * 1024)
    free(cbor_buf.ptr);
    free(signed_cose.ptr);
#endif

    return EXIT_SUCCESS;
}
