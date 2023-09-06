/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "teep/teep_cose.h"
#include "teep/teep_message_data.h"
#include "teep/teep_message_print.h"
#include "teep_examples_common.h"


#define MAX_FILE_BUFFER_SIZE                ( 4 * 1024 * 1024)

#if TEEP_ACTOR_AGENT == 1
#include "tam_es256_public_key.h"
const unsigned char *teep_public_key = tam_es256_public_key;
#elif TEEP_ACTOR_TAM == 1
#include "teep_agent_es256_public_key.h"
const unsigned char *teep_public_key = teep_agent_es256_public_key;
#elif TEEP_ACTOR_VERIFIER == 1
#include "verifier_es256_public_key.h"
const unsigned char *teep_public_key = verifier_es256_public_key;
#else
const unsigned char *teep_public_key = NULL;
#endif

#ifdef PARSE_SUIT
#include "trust_anchor_prime256v1_pub.h"
const unsigned char *suit_manifest_key = trust_anchor_prime256v1_public_key;
#else
const unsigned char *suit_manifest_key = NULL;
#endif

int main(int argc, const char * argv[])
{
    int32_t result;
    const char *cbor_file_name = NULL;

    if (argc < 2) {
        printf("%s <CBOR file path>\n", argv[0]);
        return EXIT_FAILURE;
    }
    cbor_file_name = argv[1];

    teep_mechanism_t mechanism;
    result = teep_key_init_es256_public_key(teep_public_key, NULLUsefulBufC, &mechanism.key);
    if (result != TEEP_SUCCESS) {
        printf("main : Failed to parse t_cose_key. (%d)\n", result);
    }
    mechanism.use = true;
    printf("public_key : ");
    teep_print_hex(teep_public_key, PRIME256V1_PUBLIC_KEY_LENGTH);
    printf("\n");

    // Read cbor file.
    UsefulBuf cbor_buf = (UsefulBuf) {
        .ptr = malloc(MAX_FILE_BUFFER_SIZE),
        .len = MAX_FILE_BUFFER_SIZE
    };
    if (cbor_buf.ptr == NULL) {
        printf("main : Memory allocation failure.\n");
        return EXIT_FAILURE;
    }

    printf("main : Read CBOR file.\n");
    cbor_buf.len = read_from_file(cbor_file_name, cbor_buf.ptr, MAX_FILE_BUFFER_SIZE);
    if (cbor_buf.len == 0) {
        printf("main : Failed to read CBOR file.\n");
        return EXIT_FAILURE;
    }
    teep_print_hex_within_max(cbor_buf.ptr, cbor_buf.len, 1024);
    printf("\n");

    // Verify cbor file.
    printf("main : Verify CBOR file.\n");
    UsefulBufC signed_cose = UsefulBuf_Const(cbor_buf);
    UsefulBufC returned_payload;

    printf("main : Try to parse as COSE_Sign1.\n");
    mechanism.cose_tag = CBOR_TAG_COSE_SIGN1;
    result = teep_verify_cose_sign1(signed_cose, &mechanism, &returned_payload);

    if (result != TEEP_SUCCESS) {
        printf("main : Try to parse as COSE_Sign.\n");
        mechanism.cose_tag = CBOR_TAG_COSE_SIGN;
        result = teep_verify_cose_sign(signed_cose, &mechanism, 1, &returned_payload);
    }

    if (result != TEEP_SUCCESS) {
#ifdef ALLOW_CBOR_WITHOUT_SIGN1
        printf("main : Failed to verify CBOR file, treat this as raw cbor.\n");
        returned_payload = cbor_buf;
#else
        printf("main : Failed to verify CBOR file. %s(%d)\n", teep_err_to_str(result), result);
        return EXIT_FAILURE;
#endif
    }
    else {
        printf("main : Success to verify. Print cose payload.\n");
    }

    // Print teep message.
    printf("\nmain : TEEP message in hex.\n");
    teep_print_hex_within_max(returned_payload.ptr, returned_payload.len, 1024);
    printf("\n");

#if TEEP_ACTOR_VERIFIER != 1
    printf("\nmain : TEEP message with COSE wrapper.\n");
    teep_print_cose_teep_message(signed_cose, 0, 2);

    // Parse teep message.
    teep_message_t msg = { 0 };
    result = teep_set_message_from_bytes(returned_payload.ptr, returned_payload.len, &msg);
    if (result != TEEP_SUCCESS) {
        printf("main : Failed to parse CBOR as teep-message. %s(%d)\n", teep_err_to_str(result), result);
        return EXIT_FAILURE;
    }

    printf("\nmain : parsed teep_message_t data.\n");
    result = teep_print_message(&msg, 0, 2, suit_manifest_key);
    if (result != TEEP_SUCCESS) {
        printf("main : Failed to print CBOR as teep-message. %s(%d)\n", teep_err_to_str(result), result);
        return EXIT_FAILURE;
    }
#else
    printf("\nmain : EAT data.\n");
    teep_print_cose_eat(signed_cose, 0, 2);
#endif
    teep_free_key(&mechanism.key);
    free(cbor_buf.ptr);

    return EXIT_SUCCESS;
}
