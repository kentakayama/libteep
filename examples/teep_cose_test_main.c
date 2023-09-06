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
  #define NUM_TEEP_PRIVATE_KEY 1
  UsefulBufC teep_private_keys[NUM_TEEP_PRIVATE_KEY] = {
      teep_agent_es256_cose_key_private,
  };
  UsefulBufC kids[NUM_TEEP_PRIVATE_KEY] = {
      UsefulBuf_FROM_SZ_LITERAL("101"),
  };
#elif TEEP_ACTOR_TAM0 == 1
  #if defined(LIBTEEP_PSA_CRYPTO_C)
    /* MbedTLS does not support EdDSA well, so ignore it */
    #include "tam_es256_cose_key_private.h"
    #define NUM_TEEP_PRIVATE_KEY 1
    UsefulBufC teep_private_keys[NUM_TEEP_PRIVATE_KEY] = {
        tam_es256_cose_key_private,
    };
    UsefulBufC kids[NUM_TEEP_PRIVATE_KEY] = {
        UsefulBuf_FROM_SZ_LITERAL("201"),
    };
  #else
    #include "tam_es256_cose_key_private.h"
    #include "tam_ed25519_cose_key_private.h"
    #define NUM_TEEP_PRIVATE_KEY 2
    UsefulBufC teep_private_keys[NUM_TEEP_PRIVATE_KEY] = {
        tam_es256_cose_key_private,
        tam_ed25519_cose_key_private
    };
    UsefulBufC kids[NUM_TEEP_PRIVATE_KEY] = {
        UsefulBuf_FROM_SZ_LITERAL("201"),
        UsefulBuf_FROM_SZ_LITERAL("202")
    };
  #endif
#elif TEEP_ACTOR_TAM1 == 1
  #include "tam_es256_cose_key_private.h"
  #define NUM_TEEP_PRIVATE_KEY 1
  UsefulBufC teep_private_keys[NUM_TEEP_PRIVATE_KEY] = {
      tam_es256_cose_key_private,
  };
  UsefulBufC kids[NUM_TEEP_PRIVATE_KEY] = {
      UsefulBuf_FROM_SZ_LITERAL("201"),
  };
#elif TEEP_ACTOR_VERIFIER == 1
  #include "verifier_es256_cose_key_private.h"
  #define NUM_TEEP_PRIVATE_KEY 1
  UsefulBufC teep_private_keys[NUM_TEEP_PRIVATE_KEY] = {
      verifier_es256_cose_key_private
  };
  UsefulBufC kids[NUM_TEEP_PRIVATE_KEY] = {
      UsefulBuf_FROM_SZ_LITERAL("301")
  };
#elif TEEP_ACTOR_TRUST_ANCHOR == 1
  #include "trust_anchor_prime256v1_cose_key_private.h"
  #define NUM_TEEP_PRIVATE_KEY 1
  UsefulBufC teep_private_keys[NUM_TEEP_PRIVATE_KEY] = {
      trust_anchor_prime256v1_cose_key_private
  };
  UsefulBufC kids[NUM_TEEP_PRIVATE_KEY] = {
      NULLUsefulBufC
  };
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

    teep_mechanism_t mechanisms[NUM_TEEP_PRIVATE_KEY];
    for (size_t i = 0; i < NUM_TEEP_PRIVATE_KEY; i++) {
        result = teep_set_mechanism_from_cose_key(teep_private_keys[i], kids[i], &mechanisms[i]);
        if (result != TEEP_SUCCESS) {
            printf("main : Failed to create key pair. %s(%d)\n", teep_err_to_str(result), result);
            return EXIT_FAILURE;
        }
        mechanisms[i].cose_tag = (NUM_TEEP_PRIVATE_KEY > 1) ? CBOR_TAG_COSE_SIGN : CBOR_TAG_COSE_SIGN1;
        mechanisms[i].use = true;
    }

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

#if NUM_TEEP_PRIVATE_KEY > 1
    result = teep_sign_cose_sign(UsefulBuf_Const(cbor_buf), mechanisms, NUM_TEEP_PRIVATE_KEY, &signed_cose);
#else
    result = teep_sign_cose_sign1(UsefulBuf_Const(cbor_buf), &mechanisms[0], &signed_cose);
#endif

    if (result != TEEP_SUCCESS) {
        printf("main : Failed to sign. %s(%d)\n", teep_err_to_str(result), result);
        return EXIT_FAILURE;
    }

    teep_print_hex_within_max(signed_cose.ptr, signed_cose.len, signed_cose.len);
    printf("\n");

    // Verify cose signed file.
    UsefulBufC returned_payload;
#if NUM_TEEP_PRIVATE_KEY > 1
    result = teep_verify_cose_sign(UsefulBuf_Const(signed_cose), mechanisms, NUM_TEEP_PRIVATE_KEY, &returned_payload);
#else
    result = teep_verify_cose_sign1(UsefulBuf_Const(signed_cose), &mechanisms[0], &returned_payload);
#endif
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

    for (size_t i = 0; i < NUM_TEEP_PRIVATE_KEY; i++) {
        teep_free_key(&mechanisms[i].key);
    }

#if MAX_FILE_BUFFER_SIZE > (2 * 1024)
    free(cbor_buf.ptr);
    free(signed_cose.ptr);
#endif

    return EXIT_SUCCESS;
}
