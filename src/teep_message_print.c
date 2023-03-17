/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "teep/teep_common.h"
#include "teep/teep_message_data.h"
#include "teep/teep_message_print.h"

#ifdef PARSE_SUIT
#include "csuit/csuit.h"
#endif

const char *teep_err_to_str(teep_err_t err)
{
    switch (err) {
    case TEEP_SUCCESS:
        return "SUCCESS";
    case TEEP_ERR_INVALID_TYPE_OF_ARGUMENT:
        return "INVALID_TYPE_OF_ARGUMENT";
    case TEEP_ERR_INVALID_VALUE:
        return "INVALID_VALUE";
    case TEEP_ERR_INVALID_LENGTH:
        return "INVALID_LENGTH";
    case TEEP_ERR_INVALID_MESSAGE_TYPE:
        return "INVALID_MESSAGE_TYPE";
    case TEEP_ERR_CBOR_WITHOUT_COSE:
        return "CBOR_WITHOUT_COSE";
    case TEEP_ERR_VERIFICATION_FAILED:
        return "VERIFICATION_FAILED";
    case TEEP_ERR_SIGNING_FAILED:
        return "SIGNING_FAILED";
    case TEEP_ERR_NO_SUPPORTED_VERSION:
        return "NO_SUPPORTED_VERSION";
    case TEEP_ERR_NO_SUPPORTED_CIPHERSUITE:
        return "NO_SUPPORTED_CIPHERSUITE";
    case TEEP_ERR_NO_MEMORY:
        return "NO_MEMORY";
    case TEEP_ERR_ON_HTTP_POST:
        return "ON_HTTP_POST";
    case TEEP_ERR_UNEXPECTED_ERROR:
        return "UNEXPECTED_ERROR";
    case TEEP_ERR_ABORT:
        return "ABORT";
    case TEEP_ERR_FATAL:
        return "FATAL";
    default:
        return "UNKNOWN";
    }
}

teep_err_t teep_print_hex(const uint8_t *array, const size_t size)
{
    if (array == NULL) {
        return TEEP_ERR_FATAL;
    }
    printf("h'");
    for (size_t i = 0; i < size; i++) {
        printf("%02x", (unsigned char)array[i]);
    }
    printf("'");
    return TEEP_SUCCESS;
}

teep_err_t teep_print_hex_within_max(const uint8_t *array,
                                     const size_t size,
                                     const size_t size_max)
{
    teep_err_t result = TEEP_SUCCESS;
    if (size <= size_max) {
        result = teep_print_hex(array, size);
    }
    else {
        result = teep_print_hex(array, size_max);
        printf("..");
    }
    return result;
}

teep_err_t teep_print_text(const char *text, const size_t size)
{
    if (text == NULL) {
        return TEEP_ERR_UNEXPECTED_ERROR;
    }

    printf("\"");
    for (size_t i = 0; i < size; i++) {
        if (text[i] == '\n') {
            putchar('\\'); putchar('n');
        }
        else {
            putchar(text[i]);
        }
    }
    printf("\"");
    return TEEP_SUCCESS;
}

teep_err_t teep_print_text_within_max(const char *text,
                                      const size_t size,
                                      const size_t size_max)
{
    teep_err_t result = TEEP_SUCCESS;
    if (size <= size_max) {
        result = teep_print_text(text, size);
    }
    else {
        result = teep_print_text(text, size_max);
        printf("..");
    }
    return result;
}

teep_err_t teep_print_string(const teep_buf_t *string)
{
    return teep_print_text_within_max((const char *)string->ptr, string->len, TEEP_MAX_PRINT_TEXT_COUNT);
}

const char *teep_err_code_to_str(int32_t err_code)
{
    switch (err_code) {
    case TEEP_ERR_CODE_PERMANENT_ERROR:
        return "ERR_PERMANENT_ERROR";
    case TEEP_ERR_CODE_UNSUPPORTED_EXTENSION:
        return "ERR_UNSUPPORTED_EXTENSION";
    case TEEP_ERR_CODE_UNSUPPORTED_FRESHNESS_MECHANISMS:
        return "ERR_UNSUPPORTED_FRESHNESS_MECHANISMS";
    case TEEP_ERR_CODE_UNSUPPORTED_MSG_VERSION:
        return "ERR_UNSUPPORTED_MSG_VERSION";
    case TEEP_ERR_CODE_UNSUPPORTED_CIPHER_SUITES:
        return "ERR_UNSUPPORTED_CIPHER_SUITES";
    case TEEP_ERR_CODE_BAD_CERTIFICATE:
        return "ERR_BAD_CERTIFICATE";
    case TEEP_ERR_CODE_CERTIFICATE_EXPIRED:
        return "ERR_CERTIFICATE_EXPIRED";
    case TEEP_ERR_CODE_TEMPORARY_ERROR:
        return "ERR_TEMPORARY_ERROR";
    case TEEP_ERR_CODE_MANIFEST_PROCESSING_FAILED:
        return "ERR_MANIFEST_PROCESSING_FAILED";
    default:
        return "ERR_UNKNOWN";
    }
}

const char *teep_cose_mechanism_key_to_str(int64_t cose_mechanism_key)
{
    switch (cose_mechanism_key) {
    case CBOR_TAG_COSE_SIGN1:
        return "COSE_Sign1";
    case CBOR_TAG_SIGN:
        return "COSE_Sign";
    case CBOR_TAG_COSE_MAC0:
        return "COSE_Mac0";
    case CBOR_TAG_MAC:
        return "COSE_Mac";
    case CBOR_TAG_COSE_ENCRYPT0:
        return "COSE_Encrypt0";
    case CBOR_TAG_ENCRYPT:
        return "COSE_Encrypt";
    default:
        return "(NULL)";
    }
}

const char *teep_cose_algs_key_to_str(int64_t cose_algs_key)
{
    switch (cose_algs_key) {
    case 0:
        return "NONE";
    case TEEP_COSE_SIGN_ES256:
        return "ES256";
    case TEEP_COSE_SIGN_EDDSA:
        return "EdDSA";
    case TEEP_COSE_SIGN_HSS_LMS:
        return "HSS-LMS";
    case TEEP_COSE_ENCRYPT_A256_GCM:
        return "AES-GCM-256";
    case TEEP_COSE_ENCRYPT_ACCM_16_64_128:
        return "AES-CCM-16-64-128";
    case TEEP_COSE_MAC_HMAC256:
        return "HMAC 256/256";
    default:
        return "UNKNOWN";
    }
}

void teep_debug_print(QCBORDecodeContext *message,
                      QCBORItem *item,
                      QCBORError *error,
                      const char *func_name,
                      uint8_t expecting)
{
    size_t cursor = UsefulInputBuf_Tell(&message->InBuf);
    size_t len = UsefulInputBuf_GetBufferLength(&message->InBuf) - cursor;
    uint8_t *at = (uint8_t *)message->InBuf.UB.ptr + cursor;

    len = (len > 12) ? 12 : len;

    printf("DEBUG: %s\n", func_name);
    printf("msg[%ld:%ld] = ", cursor, cursor + len);
    teep_print_hex_within_max(at, len, len);
    printf("\n");

    if (error != NULL && *error != QCBOR_SUCCESS) {
        printf("    Error! nCBORError = %d\n", *error);
    }
    if (expecting != QCBOR_TYPE_ANY && expecting != item->uDataType) {
        printf("    item->uDataType %d != %d\n", item->uDataType, expecting);
    }
}

teep_err_t teep_print_cipher_suite(const teep_cipher_suite_t *cipher_suite)
{
    if (cipher_suite == NULL) {
        return TEEP_ERR_UNEXPECTED_ERROR;
    }
    printf("[");
    bool printed = false;
    for (size_t i = 0; i < TEEP_MAX_CIPHER_SUITES_LENGTH; i++) {
        if (!teep_is_valid_mechanism(cipher_suite->mechanisms[i].cose_tag)) {
            break;
        }
        if (printed) {
            printf(", ");
        }
        printf("[ / mechanism: / %d / (%s), / algorithm_id: / %d / (%s) / ]",
            cipher_suite->mechanisms[i].cose_tag,
            teep_cose_mechanism_key_to_str(cipher_suite->mechanisms[i].cose_tag),
            cipher_suite->mechanisms[i].algorithm_id,
            teep_cose_algs_key_to_str(cipher_suite->mechanisms[i].algorithm_id)
        );
        printed = true;
    }
    printf("]");
    return TEEP_SUCCESS;
}

void teep_print_data_item_requested(teep_data_item_requested_t requested)
{
    bool printed = false;
    if (requested.attestation) {
        if (printed) {
            printf(" | ");
        }
        printf("\"attestation\"");
        printed = true;
    }
    if (requested.trusted_components) {
        if (printed) {
            printf(" | ");
        }
        printf("\"trusted-components\"");
        printed = true;
    }
}

teep_err_t teep_print_query_request(const teep_query_request_t *query_request,
                                    uint32_t indent_space,
                                    uint32_t indent_delta)
{
    if (query_request == NULL) {
        return TEEP_ERR_UNEXPECTED_ERROR;
    }
    teep_err_t result = TEEP_SUCCESS;
    printf("%*s/ QueryRequest = / [\n", indent_space, "");
    printf("%*s/ type : / %u,\n", indent_space + indent_delta, "", query_request->type);

    printf("%*s/ options : / {\n", indent_space + indent_delta, "");
    bool printed = false;
    if (query_request->contains & TEEP_MESSAGE_CONTAINS_TOKEN) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ token : / ", indent_space + 2 * indent_delta, "");
        teep_print_hex(query_request->token.ptr, query_request->token.len);
    }
    if (query_request->contains & TEEP_MESSAGE_CONTAINS_SUPPORTED_FRESHNESS_MECHANISMS) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ supported-freshness-mechanisms / %d : [ ", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_SUPPORTED_FRESHNESS_MECHANISMS);
        for (size_t i = 0; i < query_request->supported_freshness_mechanisms.len; i++) {
            printf("%u, ", query_request->supported_freshness_mechanisms.items[i]);
        }
        printf("]");
    }
    if (query_request->contains & TEEP_MESSAGE_CONTAINS_CHALLENGE) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ challenge / %d :", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_CHALLENGE);
        result = teep_print_hex(query_request->challenge.ptr, query_request->challenge.len);
        if (result != TEEP_SUCCESS) {
            return result;
        }
    }
    if (query_request->contains & TEEP_MESSAGE_CONTAINS_VERSIONS) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ versions / %d :  [ ", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_VERSIONS);
        for (size_t i = 0; i < query_request->versions.len; i++) {
            printf("%u", query_request->versions.items[i]);
            if (i + 1 < query_request->versions.len) {
                printf(", ");
            }
        }
        printf(" ]");
    }
    printf("\n%*s},\n", indent_space + indent_delta, "");

    printf("%*s/ supported-teep-cipher-suites : / [\n", indent_space + indent_delta, "");
    for (size_t i = 0; i < query_request->supported_cipher_suites.len; i++) {
        printf("%*s", indent_space + 2 * indent_delta, "");
        result = teep_print_cipher_suite(&query_request->supported_cipher_suites.items[i]);
        if (result != TEEP_SUCCESS) {
            return result;
        }
        if (i + 1 < query_request->supported_cipher_suites.len) {
            printf(",");
        }
        printf("\n");
    }
    printf("%*s],\n", indent_space + indent_delta, "");
    printf("%*s/ data-item-requested : / %u / (", indent_space + indent_delta, "", query_request->data_item_requested.val);
    teep_print_data_item_requested(query_request->data_item_requested);
    printf(") /\n");
    printf("%*s]\n", indent_space, "");
    return TEEP_SUCCESS;
}

teep_err_t teep_print_component_id(const teep_buf_t *component_id)
{
    if (component_id == NULL) {
        return TEEP_ERR_UNEXPECTED_ERROR;
    }
    teep_err_t result = TEEP_SUCCESS;
#ifdef PARSE_SUIT
    suit_buf_t buf = {.ptr = component_id->ptr, .len = component_id->len};
    suit_component_identifier_t identifier;
    suit_err_t suit_result = suit_set_component_identifiers(SUIT_DECODE_MODE_SKIP_ANY_ERROR, &buf, &identifier);
    if (suit_result != SUIT_SUCCESS) {
        return TEEP_ERR_UNEXPECTED_ERROR;
    }
    suit_result = suit_print_component_identifier(&identifier);
    if (suit_result != SUIT_SUCCESS) {
        return TEEP_ERR_UNEXPECTED_ERROR;
    }
#else
    result = teep_print_hex(component_id->ptr, component_id->len);
#endif /* PARSE_SUIT */
    return result;
}

teep_err_t teep_print_query_response(const teep_query_response_t *query_response,
                                     uint32_t indent_space,
                                     uint32_t indent_delta)
{
    if (query_response == NULL) {
        return TEEP_ERR_UNEXPECTED_ERROR;
    }
    teep_err_t result = TEEP_SUCCESS;
    printf("%*s/ QueryResponse = / [\n", indent_space, "");
    printf("%*s/ type : / %u,\n", indent_space + indent_delta, "", query_response->type);
    printf("%*s/ options : / {\n", indent_space + indent_delta, "");
    bool printed = false;
    if (query_response->contains & TEEP_MESSAGE_CONTAINS_TOKEN) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ token / %d : ", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_TOKEN);
        teep_print_hex(query_response->token.ptr, query_response->token.len);
    }
    if (query_response->contains & TEEP_MESSAGE_CONTAINS_SELECTED_TEEP_CIPHER_SUITE) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ selected-teep-cipher-suite / %d : ", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_SELECTED_TEEP_CIPHER_SUITE);
        result = teep_print_cipher_suite(&query_response->selected_cipher_suite);
        if (result != TEEP_SUCCESS) {
            return result;
        }
    }
    if (query_response->contains & TEEP_MESSAGE_CONTAINS_SELECTED_VERSION) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ selected-version / %d : %u", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_SELECTED_VERSION, query_response->selected_version);
    }
    if (query_response->contains & TEEP_MESSAGE_CONTAINS_ATTESTATION_PAYLOAD_FORMAT) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ attestation-payload-format / %d : ", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_ATTESTATION_PAYLOAD_FORMAT);
        result = teep_print_string(&query_response->attestation_payload_format);
        if (result != TEEP_SUCCESS) {
            return result;
        }
    }
    if (query_response->contains & TEEP_MESSAGE_CONTAINS_ATTESTATION_PAYLOAD) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ attestation-payload / %d : ", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_ATTESTATION_PAYLOAD);
        result = teep_print_hex(query_response->attestation_payload.ptr, query_response->attestation_payload.len);
        if (result != TEEP_SUCCESS) {
            return result;
        }
    }
    if (query_response->contains & TEEP_MESSAGE_CONTAINS_TC_LIST) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ tc-list / %d : [\n", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_TC_LIST);
        for (size_t i = 0; i < query_response->tc_list.len; i++) {
            printf("%*s", indent_space + 3 * indent_delta, "");
            teep_print_hex(query_response->tc_list.items[i].ptr, query_response->tc_list.items[i].len);
            if (i + 1 < query_response->tc_list.len) {
                printf(",\n");
            }
        }
        printf("\n%*s]", indent_space + 2 * indent_delta, "");
    }
    if (query_response->contains & TEEP_MESSAGE_CONTAINS_REQUESTED_TC_LIST) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ requested-tc-list / %d : [\n", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_REQUESTED_TC_LIST);
        for (size_t i = 0; i < query_response->requested_tc_list.len; i++) {
            printf("%*s{\n", indent_space + 3 * indent_delta, "");
            if (query_response->requested_tc_list.items[i].contains & TEEP_MESSAGE_CONTAINS_COMPONENT_ID) {
                printf("%*s/ component-id : / ", indent_space + 4 * indent_delta, "");
                result = teep_print_component_id(&query_response->requested_tc_list.items[i].component_id);
                if (result != TEEP_SUCCESS) {
                    return result;
                }
            }
            if (query_response->requested_tc_list.items[i].contains & TEEP_MESSAGE_CONTAINS_TC_MANIFEST_SEQUENCE_NUMBER) {
                printf(",\n%*s/ tc-manifest-sequence-number : / %lu,\n", indent_space + 4 * indent_delta, "", query_response->requested_tc_list.items[i].tc_manifest_sequence_number);
            }
            if (query_response->requested_tc_list.items[i].contains & TEEP_MESSAGE_CONTAINS_HAVE_BINARY) {
                printf(",\n%*s/ have-binary : / %s,\n", indent_space + 4 * indent_delta, "", (query_response->requested_tc_list.items[i].have_binary) ? "true" : "false");
            }
            printf("\n%*s}\n", indent_space + 3 * indent_delta, "");
        }
        printf("%*s]\n", indent_space + 2 * indent_delta, "");
    }
    if (query_response->contains & TEEP_MESSAGE_CONTAINS_EXT_LIST) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*sext-list : [", indent_space + 2 * indent_delta, "");
        for (size_t i = 0; i < query_response->ext_list.len; i++) {
            printf("%lu ", query_response->ext_list.items[i]);
        }
        printf("]");
    }

    printf("\n%*s}\n%*s]\n", indent_space + indent_delta, "", indent_space, "");
    return TEEP_SUCCESS;
}

teep_err_t teep_print_update(const teep_update_t *teep_update,
                             uint32_t indent_space,
                             uint32_t indent_delta,
                             const char *ta_public_key)
{
    if (teep_update == NULL) {
        return TEEP_ERR_UNEXPECTED_ERROR;
    }
    teep_err_t result = TEEP_SUCCESS;
    printf("%*s/ Update = / [\n", indent_space, "");
    printf("%*s/ type : / %u,\n", indent_space + indent_delta, "", teep_update->type);
    printf("%*s/ options : {\n", indent_space + indent_delta, "");
    bool printed = false;
    if (teep_update->contains & TEEP_MESSAGE_CONTAINS_TOKEN) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ token / %d : ", indent_space + indent_delta, "", TEEP_OPTIONS_KEY_TOKEN);
        teep_print_hex(teep_update->token.ptr, teep_update->token.len);
    }
    if (teep_update->contains & TEEP_MESSAGE_CONTAINS_UNNEEDED_TC_LIST) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ unneeded-tc-list / %d : [\n", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_UNNEEDED_TC_LIST);
        for (size_t i = 0; i < teep_update->unneeded_tc_list.len; i++) {
            printf("%*s", indent_space + 3 * indent_delta, "");
            result = teep_print_component_id(&teep_update->unneeded_tc_list.items[i]);
            if (result != TEEP_SUCCESS) {
                return result;
            }
        }
        printf("\n%*s]", indent_space + 2 * indent_delta, "");
    }
    if (teep_update->contains & TEEP_MESSAGE_CONTAINS_MANIFEST_LIST) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ manifest-list / %d : [\n", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_MANIFEST_LIST);
        for (size_t i = 0; i < teep_update->manifest_list.len; i++) {
#ifdef PARSE_SUIT
            suit_buf_t buf = {.ptr = teep_update->manifest_list.items[i].ptr, .len = teep_update->manifest_list.items[i].len};
            suit_envelope_t envelope;
            suit_err_t suit_result = suit_set_envelope(SUIT_DECODE_MODE_SKIP_ANY_ERROR, &buf, &envelope, ta_public_key);
            if (suit_result != SUIT_SUCCESS) {
                return TEEP_ERR_UNEXPECTED_ERROR;
            }
            suit_result = suit_print_envelope(SUIT_DECODE_MODE_SKIP_ANY_ERROR, &envelope, indent_space + 6);
            if (result != SUIT_SUCCESS) {
                return TEEP_ERR_UNEXPECTED_ERROR;
            }
#else
            printf("%*s", indent_space + 3 * indent_delta, "");
            result = teep_print_hex_within_max(teep_update->manifest_list.items[i].ptr, teep_update->manifest_list.items[i].len, TEEP_MAX_PRINT_BYTE_COUNT);
            if (result != TEEP_SUCCESS) {
                return result;
            }
#endif /* PARSE_SUIT */
        }
        printf("%*s]", indent_space + 2 * indent_delta, "");
    }
    printf("\n%*s}\n%*s]\n", indent_space + indent_delta, "", indent_space, "");
    return TEEP_SUCCESS;
}

teep_err_t teep_print_error(const teep_error_t *teep_error,
                            uint32_t indent_space,
                            uint32_t indent_delta)
{
    if (teep_error == NULL) {
        return TEEP_ERR_UNEXPECTED_ERROR;
    }
    teep_err_t result = TEEP_SUCCESS;
    printf("%*s/ Error = / [\n", indent_space, "");
    printf("%*s/ type : / %u, \n", indent_space + indent_delta, "", teep_error->type);
    printf("%*s/ options : / {\n", indent_space + indent_delta, "");
    bool printed = false;
    if (teep_error->contains & TEEP_MESSAGE_CONTAINS_TOKEN) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ token / %d : ", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_TOKEN);
        teep_print_hex(teep_error->token.ptr, teep_error->token.len);
    }
    if (teep_error->contains & TEEP_MESSAGE_CONTAINS_ERR_MSG) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ err-msg / %d : ", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_ERR_MSG);
        result = teep_print_text((const char *)teep_error->err_msg.ptr, teep_error->err_msg.len);
        if (result != TEEP_SUCCESS) {
            return result;
        }
    }
    if (teep_error->contains & TEEP_MESSAGE_CONTAINS_SUPPORTED_TEEP_CIPHER_SUITES) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ supported-teep-cipher-suites / %d : [\n", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_SUPPORTED_TEEP_CIPHER_SUITES);
        for (size_t i = 0; i < teep_error->supported_cipher_suites.len; i++) {
            printf("%*s", indent_space + 6, "");
            result = teep_print_cipher_suite(&teep_error->supported_cipher_suites.items[i]);
            if (result != TEEP_SUCCESS) {
                return result;
            }
            printf(",\n");
        }
        printf("%*s]", indent_space + 2 * indent_delta, "");
    }
    if (teep_error->contains & TEEP_MESSAGE_CONTAINS_VERSIONS) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ versions / %d : [ ", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_VERSIONS);
        for (size_t i = 0; i < teep_error->versions.len; i++) {
            printf("%u", teep_error->versions.items[i]);
            if (i + 1 < teep_error->versions.len) {
                printf(",");
            }
        }
        printf("]");
    }
    printf("\n%*s},\n", indent_space + indent_delta, "");
    printf("%*s/ err-code : / %u / (%s) /\n", indent_space + indent_delta, "", teep_error->err_code, teep_err_code_to_str(teep_error->err_code));
    printf("%*s]\n", indent_space, "");
    return TEEP_SUCCESS;
}

teep_err_t teep_print_success(const teep_success_t *teep_success,
                              uint32_t indent_space,
                              uint32_t indent_delta)
{
    if (teep_success == NULL) {
        return TEEP_ERR_UNEXPECTED_ERROR;
    }
    teep_err_t result;
    printf("%*s/ Success = / [\n", indent_space, "");
    printf("%*s/ type : / %u,\n", indent_space + indent_delta, "", teep_success->type);
    printf("%*s/ options : {\n", indent_space + indent_delta, "");
    bool printed = false;
    if (teep_success->contains & TEEP_MESSAGE_CONTAINS_TOKEN) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ token / %d : ", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_TOKEN);
        teep_print_hex(teep_success->token.ptr, teep_success->token.len);
    }
    if (teep_success->contains & TEEP_MESSAGE_CONTAINS_MSG) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ msg / %d : ", indent_space + indent_delta, "", TEEP_OPTIONS_KEY_MSG);
        result = teep_print_text((const char *)teep_success->msg.ptr, teep_success->msg.len);
        if (result != TEEP_SUCCESS) {
            return result;
        }
    }
    printf("\n%*s}\n%*s]\n", indent_space + indent_delta, "", indent_space, "");
    return TEEP_SUCCESS;
}

teep_err_t teep_print_message(const teep_message_t *msg,
                              uint32_t indent_space,
                              uint32_t indent_delta,
                              const char *ta_public_key) {
    if (msg == NULL) {
        return TEEP_ERR_UNEXPECTED_ERROR;
    }
    teep_err_t result = TEEP_SUCCESS;
    switch (msg->teep_message.type) {
        case TEEP_TYPE_QUERY_REQUEST:
            result = teep_print_query_request(&msg->query_request, indent_space, indent_delta);
            break;
        case TEEP_TYPE_QUERY_RESPONSE:
            result = teep_print_query_response(&msg->query_response, indent_space, indent_delta);
            break;
        case TEEP_TYPE_UPDATE:
            result = teep_print_update(&msg->teep_update, indent_space, indent_delta, ta_public_key);
            break;
        case TEEP_TYPE_TEEP_SUCCESS:
            result = teep_print_success(&msg->teep_success, indent_space, indent_delta);
            break;
        case TEEP_TYPE_TEEP_ERROR:
            result = teep_print_error(&msg->teep_error, indent_space, indent_delta);
            break;
        default:
            result = TEEP_ERR_INVALID_MESSAGE_TYPE;
            break;
    }
    return result;
}
