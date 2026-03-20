/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <unistd.h>
#include "teep/teep_message_data.h"
#include "teep/teep_message_print.h"
#include "teep_examples_common.h"
#include "teep_http_client.h"

#include "teep_agent_es256_private_key.h"
#include "teep_agent_es256_public_key.h"
const unsigned char *teep_agent_private_key = teep_agent_es256_private_key;
const unsigned char *teep_agent_public_key = teep_agent_es256_public_key;
#include "tam_es256_public_key.h"
const unsigned char *tam_public_key = tam_es256_public_key;

const char DEFAULT_TAM_URL[] =          "http://localhost:8080/tam";
#define MAX_RECEIVE_BUFFER_SIZE         1024
#define MAX_SEND_BUFFER_SIZE            1024
#define MAX_FILE_BUFFER_SIZE            512

#define SUPPORTED_VERSION               0
#define SUPPORTED_CIPHER_SUITES_LEN     2
#define SUPPORTED_SUIT_PROFILES_LEN     2
#define ERR_MSG_BUF_LEN                 32
const teep_cipher_suite_t supported_teep_cipher_suites[SUPPORTED_CIPHER_SUITES_LEN] = {
    {
        .mechanisms[0] = {
            .cose_tag = CBOR_TAG_COSE_SIGN1,
            .algorithm_id = TEEP_COSE_SIGN_ESP256,
        },
        .mechanisms[1] = {
            0
        }
    },
    {
        .mechanisms[0] = {
            .cose_tag = CBOR_TAG_COSE_SIGN1,
            .algorithm_id = TEEP_COSE_SIGN_ED25519,
        },
        .mechanisms[1] = {
            0
        }
    }
};
const teep_suit_cose_profile_t supported_suit_cose_profiles[SUPPORTED_SUIT_PROFILES_LEN] = {
    { TEEP_COSE_SHA256, TEEP_COSE_SIGN_ESP256, TEEP_COSE_ECDHES_A128KW, TEEP_COSE_ENCRYPT_A128CTR },
    { TEEP_COSE_SHA256, TEEP_COSE_SIGN_ED25519, TEEP_COSE_ECDHES_A128KW, TEEP_COSE_ENCRYPT_A128CTR },
};

void useful_buf_strncpy(const char *err_msg,
                        const size_t len,
                        UsefulBuf *dst)
{
    strncpy(dst->ptr, err_msg, len); // '\0' may not be appended at the last
    dst->len = strnlen(dst->ptr, len);
}

/*!
    \brief      Create teep-error message.

    \param[in]  token       Bstr token in sent message from the TAM.
    \param[in]  err_code    Integer err-code message set by caller.
    \param[in]  err_msg_buf Tstr err-msg set by caller.
    \param[out] message     Pointer of returned struct.

    \return     This returns only TEEP_SUCCESS;
 */
teep_err_t create_error(teep_buf_t token,
                        uint64_t err_code,
                        UsefulBuf err_msg_buf,
                        teep_message_t *message)
{
    teep_error_t *error = (teep_error_t *)message;
    error->type = TEEP_TYPE_ERROR;
    error->contains = 0;

    if (token.ptr != NULL && 8 <= token.len && token.len <= 64) {
        error->token = token;
        error->contains |= TEEP_MESSAGE_CONTAINS_TOKEN;
    }
    if (err_msg_buf.len > 0) {
        error->err_msg = (teep_buf_t){.ptr = err_msg_buf.ptr, .len = err_msg_buf.len};
        error->contains |= TEEP_MESSAGE_CONTAINS_ERR_MSG;
    }

    if (err_code == TEEP_ERR_CODE_UNSUPPORTED_MSG_VERSION) {
        error->versions.len = 1;
        error->versions.items[0] = SUPPORTED_VERSION;
        error->contains |= TEEP_MESSAGE_CONTAINS_VERSIONS;
    }
    else if (err_code == TEEP_ERR_CODE_UNSUPPORTED_CIPHER_SUITES) {
        error->supported_teep_cipher_suites.len = SUPPORTED_CIPHER_SUITES_LEN;
        for (size_t i = 0; i < SUPPORTED_CIPHER_SUITES_LEN; i++) {
            error->supported_teep_cipher_suites.items[i] = supported_teep_cipher_suites[i];
        }
        error->contains |= TEEP_MESSAGE_CONTAINS_SUPPORTED_TEEP_CIPHER_SUITES;
    }
    else if (err_code == TEEP_ERR_CODE_UNSUPPORTED_SUIT_REPORT) {
        error->supported_suit_cose_profiles.len = SUPPORTED_SUIT_PROFILES_LEN;
        for (size_t i = 0; i < SUPPORTED_SUIT_PROFILES_LEN; i++) {
            error->supported_suit_cose_profiles.items[i] = supported_suit_cose_profiles[i];
        }
        error->contains |= TEEP_MESSAGE_CONTAINS_SUPPORTED_SUIT_COSE_PROFILES;
    }
    error->err_code = err_code;
    return TEEP_SUCCESS;
}

/*!
    \brief      Create teep-success or teep-error message as a response to the teep-update message.

    \param[in]  update      Received teep-update message from the TAM.
    \param[in]  err_msg_buf Tstr err-msg buffer allocated by caller.
    \param[out] message     Pointer of returned struct.

    \return     This returns only TEEP_SUCCESS;
 */
teep_err_t create_success_or_error(const teep_update_t *update,
                                   UsefulBuf err_msg_buf,
                                   teep_message_t *message)
{
    if (!(update->contains & TEEP_MESSAGE_CONTAINS_TOKEN) ||
        update->token.len < 8 || 64 < update->token.len) {
        useful_buf_strncpy("INVALID TOKEN", ERR_MSG_BUF_LEN, &err_msg_buf);
        return create_error(update->token, TEEP_ERR_CODE_PERMANENT_ERROR, err_msg_buf, message);
    }

    /* TODO: Process SUIT Manifest
     * MAY cause TEEP_ERR_CODE_TEMPORARY_ERROR, ERR_MANIFEST_PROCESSING_FAILED
     */

    // create SUCCESS message
    teep_success_t *success = (teep_success_t *)message;
    success->type = TEEP_TYPE_SUCCESS;
    success->contains = TEEP_MESSAGE_CONTAINS_TOKEN;
    success->token = update->token;
    return TEEP_SUCCESS;
}

/*!
    \brief      Create teep-query-response or teep-error message as a response to the teep-query-request message.

    \param[in]  update      Received teep-query-request message from the TAM.
    \param[in]  err_msg_buf Tstr err-msg buffer allocated by caller.
    \param[out] message     Pointer of returned struct.

    \return     This returns only TEEP_SUCCESS;
 */
teep_err_t create_query_response_or_error(const teep_query_request_t *query_request,
                                          UsefulBuf err_msg_buf,
                                          teep_message_t *message)
{
    size_t i;
    int32_t version = -1;
    teep_cipher_suite_t cipher_suite = TEEP_CIPHER_SUITE_INVALID;

    if (query_request->contains & TEEP_MESSAGE_CONTAINS_VERSIONS) {
        for (i = 0; i < query_request->versions.len; i++) {
            if (query_request->versions.items[i] == SUPPORTED_VERSION) {
                /* supported version is found */
                version = SUPPORTED_VERSION;
                break;
            }
        }
    }
    else {
        /* means version=0 is supported */
        version = 0;
    }
    if (version != SUPPORTED_VERSION) {
        return create_error(query_request->token, TEEP_ERR_CODE_UNSUPPORTED_MSG_VERSION, err_msg_buf, message);
    }

    if (!(query_request->contains & TEEP_MESSAGE_CONTAINS_SUPPORTED_TEEP_CIPHER_SUITES)) {
        useful_buf_strncpy("NO CIPHER SUITE", ERR_MSG_BUF_LEN, &err_msg_buf);
        return create_error(query_request->token, TEEP_ERR_CODE_UNSUPPORTED_CIPHER_SUITES, err_msg_buf, message);
    }
    for (i = 0; i < query_request->supported_teep_cipher_suites.len; i++) {
        for (size_t j = 0; j < SUPPORTED_CIPHER_SUITES_LEN; j++) {
            if (teep_cipher_suite_is_same(query_request->supported_teep_cipher_suites.items[i], supported_teep_cipher_suites[j])) {
                /* supported cipher suite is found */
                cipher_suite = supported_teep_cipher_suites[j];
                goto out;
            }
        }
    }
out:

    if (teep_cipher_suite_is_same(cipher_suite, TEEP_CIPHER_SUITE_INVALID)) {
        useful_buf_strncpy("NO SHARED CIPHER SUITE", ERR_MSG_BUF_LEN, &err_msg_buf);
        return create_error(query_request->token, TEEP_ERR_CODE_UNSUPPORTED_CIPHER_SUITES, err_msg_buf, message);
    }

    if (query_request->data_item_requested.attestation) {
        useful_buf_strncpy("ATTESTATION REQUIRED", ERR_MSG_BUF_LEN, &err_msg_buf);
        return create_error(query_request->token, TEEP_ERR_CODE_ATTESTATION_REQUIRED, err_msg_buf, message);
    }
    if (query_request->data_item_requested.suit_reports) {
        useful_buf_strncpy("SUIT REPORTS UNSUPPORTED", ERR_MSG_BUF_LEN, &err_msg_buf);
        return create_error(query_request->token, TEEP_ERR_CODE_UNSUPPORTED_SUIT_REPORT, err_msg_buf, message);
    }

    teep_query_response_t *query_response = (teep_query_response_t *)message;
    memset(query_response, 0, sizeof(teep_query_response_t));
    query_response->type = TEEP_TYPE_QUERY_RESPONSE;
    query_response->contains = TEEP_MESSAGE_CONTAINS_SELECTED_VERSION;
    if (query_request->contains & TEEP_MESSAGE_CONTAINS_TOKEN) {
        query_response->token = query_request->token;
        query_response->contains |= TEEP_MESSAGE_CONTAINS_TOKEN;
    }
    query_response->selected_version = version;

    if (query_request->data_item_requested.trusted_components) {
        query_response->contains |= TEEP_MESSAGE_CONTAINS_TC_LIST;
        // TODO encode SUIT_Component_Identifier
        // Currently no tc-list
        query_response->tc_list.len = 0;
    }

    return TEEP_SUCCESS;
}

/*!
    \brief      POST a teep-message and receive response teep-messsage.

    \param[in]  tam_url         Pointer to URI front-end of the TAM.
    \param[in]  send_buf        CBOR buffer to be sent.
    \param[in]  verifying_key   A verifycation key.
    \param[out] recv_buf        CBOR buffer to be used for received message.
    \param[out] message         Pointer of returned struct.

    \return     This returns an example-local status and writes protocol errors to `teep_result`.
 */
typedef enum teep_client_result {
    TEEP_CLIENT_RESULT_OK = 0,
    TEEP_CLIENT_RESULT_TAM_TERMINATED,
    TEEP_CLIENT_RESULT_TRANSPORT_ERROR,
    TEEP_CLIENT_RESULT_PROTOCOL_ERROR,
} teep_client_result_t;

teep_client_result_t get_teep_message(const char *tam_url,
                                      UsefulBufC send_buf,
                                      teep_mechanism_t *verifying_key,
                                      UsefulBuf recv_buf,
                                      teep_message_t *message,
                                      teep_err_t *teep_result)
{
    teep_err_t result;
    teep_http_post_result_t http_result;

    // Send TEEP/HTTP POST request.
    printf("main : Send TEEP/HTTP POST request.\n");
    teep_print_hex(send_buf.ptr, send_buf.len);
    printf("\n");
    http_result = teep_send_http_post(tam_url, send_buf, &recv_buf);
    if (http_result == TEEP_HTTP_POST_NO_CONTENT) {
        return TEEP_CLIENT_RESULT_TAM_TERMINATED;
    }
    if (http_result != TEEP_HTTP_POST_OK) {
        return TEEP_CLIENT_RESULT_TRANSPORT_ERROR;
    }

    // Verify and print QueryRequest cose.
    UsefulBufC payload;
    verifying_key->cose_tag = CBOR_TAG_COSE_SIGN1;
    result = teep_verify_cose_sign1(UsefulBuf_Const(recv_buf), verifying_key, &payload);
    if (result != TEEP_SUCCESS) {
        verifying_key->cose_tag = CBOR_TAG_COSE_SIGN;
        result = teep_verify_cose_sign(UsefulBuf_Const(recv_buf), verifying_key, 1, &payload);
    }
    if (result != TEEP_SUCCESS) {
        *teep_result = result;
        return TEEP_CLIENT_RESULT_PROTOCOL_ERROR;
    }

    result = teep_set_message_from_bytes(payload.ptr, payload.len, message);
    if (result != TEEP_SUCCESS) {
        *teep_result = result;
        return TEEP_CLIENT_RESULT_PROTOCOL_ERROR;
    }
    return TEEP_CLIENT_RESULT_OK;
}

int main(int argc, const char * argv[])
{
    teep_err_t          result;
    teep_client_result_t client_result;
    typedef enum teep_agent_status {
        WAITING_QUERY_REQUEST,
        WAITING_UPDATE_OR_QUERY_REQUEST,
    } teep_agent_status_t;
    teep_agent_status_t status = WAITING_QUERY_REQUEST;
    const char *tam_url = DEFAULT_TAM_URL;
    if (argc > 1) {
        tam_url = argv[1];
    }
    UsefulBuf_MAKE_STACK_UB(cbor_recv_buf, MAX_RECEIVE_BUFFER_SIZE);
    UsefulBuf_MAKE_STACK_UB(cbor_send_buf, MAX_SEND_BUFFER_SIZE);
    UsefulBuf_MAKE_STACK_UB(cose_send_buf, MAX_SEND_BUFFER_SIZE);

    teep_mechanism_t mechanism_sign;
    result = teep_key_init_es256_key_pair(teep_agent_es256_private_key, teep_agent_es256_public_key, NULLUsefulBufC, &mechanism_sign.key);
    if (result != TEEP_SUCCESS) {
        printf("main : Failed to create t_cose key pair. %s(%d)\n", teep_err_to_str(result), result);
        return EXIT_FAILURE;
    }

    teep_mechanism_t mechanism_verify;
    result = teep_key_init_es256_public_key(tam_es256_public_key, NULLUsefulBufC, &mechanism_verify.key);
    if (result != TEEP_SUCCESS) {
        printf("main : Failed to parse t_cose public key. %s(%d)\n", teep_err_to_str(result), result);
        return EXIT_FAILURE;
    }
    mechanism_verify.cose_tag = CBOR_TAG_COSE_SIGN1;
    printf("main : Verifying key = ");
    teep_print_hex(tam_es256_public_key, sizeof(tam_es256_public_key));
    printf("\n");

    teep_message_t send_message;
    teep_message_t recv_message;
    UsefulBuf_MAKE_STACK_UB(err_msg_buf, ERR_MSG_BUF_LEN);
    err_msg_buf.len = 0; /* the user have to aware this buffer length */

    /* the first message is NULL on teep over http */
    cose_send_buf.len = 0;

    while (1) {
        client_result = get_teep_message(tam_url, UsefulBuf_Const(cose_send_buf), &mechanism_verify, cbor_recv_buf, &recv_message, &result);
        if (client_result != TEEP_CLIENT_RESULT_OK) {
            if (client_result == TEEP_CLIENT_RESULT_TAM_TERMINATED) {
                printf("main : The TAM terminated the connection.\n");
                break;
            }
            if (client_result == TEEP_CLIENT_RESULT_PROTOCOL_ERROR &&
                result == TEEP_ERR_VERIFICATION_FAILED) {
                printf("main : Could not authenticate the TAM's message.\n");
                goto interval;
            }
            if (client_result == TEEP_CLIENT_RESULT_PROTOCOL_ERROR) {
                printf("main : Failed to parse received message. %s(%d)\n", teep_err_to_str(result), result);
            }
            else {
                printf("main : Failed to exchange a TEEP/HTTP message.\n");
            }
            return EXIT_FAILURE;
        }
        teep_print_message(&recv_message, 4, 2, NULL);

        switch (recv_message.teep_message.type) {
        case TEEP_TYPE_QUERY_REQUEST:
            result = create_query_response_or_error((const teep_query_request_t *)&recv_message, err_msg_buf, &send_message);
            break;
        case TEEP_TYPE_UPDATE:
            if (status == WAITING_QUERY_REQUEST) {
                printf("main : Received Update message without QueryRequest.\n");
                goto interval;
            }
            result = create_success_or_error((const teep_update_t *)&recv_message, err_msg_buf, &send_message);
            break;
        default:
            printf("main : Unexpected message type %d\n.", recv_message.teep_message.type);
            return EXIT_FAILURE;
        }
        if (result != TEEP_SUCCESS) {
            printf("main : Failed to create teep message. %s(%d)\n", teep_err_to_str(result), result);
            return EXIT_FAILURE;
        }

        printf("main : Sending...\n");
        teep_print_message(&send_message, 4, 2, NULL);
        if (status == WAITING_QUERY_REQUEST &&
            send_message.teep_message.type == TEEP_TYPE_QUERY_RESPONSE) {
            status = WAITING_UPDATE_OR_QUERY_REQUEST;
        }
        else if (status == WAITING_UPDATE_OR_QUERY_REQUEST &&
            send_message.teep_message.type == TEEP_TYPE_SUCCESS) {
            status = WAITING_QUERY_REQUEST;
        }

        cbor_send_buf.len = MAX_SEND_BUFFER_SIZE;
        result = teep_encode_message(&send_message, &cbor_send_buf.ptr, &cbor_send_buf.len);
        if (result != TEEP_SUCCESS) {
            printf("main : Failed to encode query_response message. %s(%d)\n", teep_err_to_str(result), result);
            return EXIT_FAILURE;
        }
        cose_send_buf.len = MAX_SEND_BUFFER_SIZE;
        mechanism_sign.cose_tag = CBOR_TAG_COSE_SIGN1;
        result = teep_sign_cose_sign1(UsefulBuf_Const(cbor_send_buf), &mechanism_sign, &cose_send_buf);
        if (result != TEEP_SUCCESS) {
            printf("main : Failed to sign to query_response message. %s(%d)\n", teep_err_to_str(result), result);
            return EXIT_FAILURE;
        }
interval:
        sleep(1);
    }

    teep_free_key(&mechanism_verify.key);
    teep_free_key(&mechanism_sign.key);
    return EXIT_SUCCESS;
}
