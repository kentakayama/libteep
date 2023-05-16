/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "teep/teep_common.h"
#include "teep/teep_message_data.h"
#include "teep/teep_message_print.h"
#include "teep/claims.h"

#ifdef PARSE_SUIT
#include "csuit/csuit.h"
#include "suit_examples_common.h"
#endif

char *teep_err_to_str(teep_err_t err)
{
    switch (err) {
    case TEEP_SUCCESS:
        return "SUCCESS";
    case TEEP_ERR_INVALID_TYPE_OF_VALUE:
        return "INVALID_TYPE_OF_VALUE";
    case TEEP_ERR_INVALID_VALUE:
        return "INVALID_VALUE";
    case TEEP_ERR_INVALID_TYPE_OF_KEY:
        return "INVALID_TYPE_OF_KEY";
    case TEEP_ERR_INVALID_KEY:
        return "INVALID_KEY";
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
    case TEEP_ERR_NOT_IMPLEMENTED:
        return "NOT_IMPLEMENTED";
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
    }
    return NULL;
}

teep_err_t teep_print_hex_string(const uint8_t *array, const int size)
{
    if (array == NULL) {
        return TEEP_ERR_FATAL;
    }
    printf("'");
    printf("%.*s", size, array);
    printf("'");
    return TEEP_SUCCESS;
}

bool teep_is_printable_char(const uint8_t c)
{
    return (' ' <= c && c <= '~');
}

bool teep_printable_hex_string(const char *array, const size_t size)
{
    size_t i;
    for (i = 0; i < size; i++) {
        if (!teep_is_printable_char(array[i])) {
            return false;
        }
    }
    return true;
}

teep_err_t teep_print_text_body(const char *text, const size_t size)
{
    for (size_t i = 0; i < size; i++) {
        if (text[i] == '\n') {
            putchar('\\'); putchar('n');
        }
        else {
            putchar(text[i]);
        }
    }
    return TEEP_SUCCESS;
}

teep_err_t teep_print_text(const char *text, const size_t size)
{
    if (text == NULL) {
        return TEEP_ERR_UNEXPECTED_ERROR;
    }

    printf("\"");
    teep_print_text_body(text, size);
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

teep_err_t teep_print_hex(const uint8_t *array, const size_t size)
{
    if (array == NULL) {
        return TEEP_ERR_FATAL;
    }
    if (teep_printable_hex_string((const char *)array, size)) {
        printf("'");
        teep_print_text_body((const char *)array, size);
        printf("'");
    }
    else {
        printf("h'");
        for (size_t i = 0; i < size; i++) {
            printf("%02x", (unsigned char)array[i]);
        }
        printf("'");
    }
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

char *teep_err_code_to_str(int32_t err_code)
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

char *teep_cose_mechanism_key_to_str(int64_t cose_mechanism_key)
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
        return NULL;
    }
}

char *teep_cose_algs_key_to_str(int64_t cose_algs_key)
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
    case TEEP_COSE_ENCRYPT_A128_GCM:
        return "AES-GCM-128";
    case TEEP_COSE_ENCRYPT_A192_GCM:
        return "AES-GCM-192";
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

teep_err_t teep_print_profile(const teep_profile_t *profile)
{
    if (profile == NULL) {
        return TEEP_ERR_UNEXPECTED_ERROR;
    }
    printf("[ %d / (%s) /, %d / (%s) / ]",
        profile->signing,
        teep_cose_algs_key_to_str(profile->signing),
        profile->encryption,
        teep_cose_algs_key_to_str(profile->encryption)
    );
    return TEEP_SUCCESS;
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
    printf("%*s/ QueryRequest(signed by \n = / [\n", indent_space, "");
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
    for (size_t i = 0; i < query_request->supported_teep_cipher_suites.len; i++) {
        printf("%*s", indent_space + 2 * indent_delta, "");
        result = teep_print_cipher_suite(&query_request->supported_teep_cipher_suites.items[i]);
        if (result != TEEP_SUCCESS) {
            return result;
        }
        if (i + 1 < query_request->supported_teep_cipher_suites.len) {
            printf(",");
        }
        printf("\n");
    }
    printf("%*s],\n", indent_space + indent_delta, "");
    printf("%*s/ supported-suit-cose-profiles : / [\n", indent_space + indent_delta, "");
    for (size_t i = 0; i < query_request->supported_suit_cose_profiles.len; i++) {
        printf("%*s", indent_space + 2 * indent_delta, "");
        result = teep_print_profile(&query_request->supported_suit_cose_profiles.items[i]);
        if (result != TEEP_SUCCESS) {
            return result;
        }
        if (i + 1 < query_request->supported_suit_cose_profiles.len) {
            printf(",");
        }
        printf("\n");
    }
    printf("%*s],\n", indent_space + indent_delta, "");
    printf("%*s/ data-item-requested : / %lu / (", indent_space + indent_delta, "", query_request->data_item_requested.val);
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
    suit_buf_t buf = {.ptr = (uint8_t *)component_id->ptr, .len = component_id->len};
    suit_component_identifier_t identifier;
    suit_err_t suit_result = suit_decode_component_identifiers(SUIT_DECODE_MODE_SKIP_ANY_ERROR, &buf, &identifier);
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
        result = teep_print_cipher_suite(&query_response->selected_teep_cipher_suite);
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
    if (query_response->contains & TEEP_MESSAGE_CONTAINS_SUIT_REPORTS) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ suit-reports / %d : [\n", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_SUIT_REPORTS);
        for (size_t i = 0; i < query_response->suit_reports.len; i++) {
            printf("%*s", indent_space + 3 * indent_delta, "");
            teep_print_hex(query_response->suit_reports.items[i].ptr, query_response->suit_reports.items[i].len);
            if (i + 1 < query_response->suit_reports.len) {
                printf(",\n");
            }
        }
    }
    if (query_response->contains & TEEP_MESSAGE_CONTAINS_TC_LIST) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ tc-list / %d : [", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_TC_LIST);
        for (size_t i = 0; i < query_response->tc_list.len; i++) {
            printf("\n%*s", indent_space + 3 * indent_delta, "");
            teep_print_hex(query_response->tc_list.items[i].ptr, query_response->tc_list.items[i].len);
            if (i + 1 < query_response->tc_list.len) {
                printf(",");
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
            printf("%*s/ component-id / %d : ", indent_space + 4 * indent_delta, "", TEEP_OPTIONS_KEY_COMPONENT_ID);
            result = teep_print_component_id(&query_response->requested_tc_list.items[i].component_id);
            if (result != TEEP_SUCCESS) {
                return result;
            }

            if (query_response->requested_tc_list.items[i].contains & TEEP_MESSAGE_CONTAINS_TC_MANIFEST_SEQUENCE_NUMBER) {
                printf(",\n%*s/ tc-manifest-sequence-number / %d : %lu", indent_space + 4 * indent_delta, "", TEEP_OPTIONS_KEY_TC_MANIFEST_SEQUENCE_NUMBER, query_response->requested_tc_list.items[i].tc_manifest_sequence_number);
            }
            if (query_response->requested_tc_list.items[i].contains & TEEP_MESSAGE_CONTAINS_HAVE_BINARY) {
                printf(",\n%*s/ have-binary / %d : %s", indent_space + 4 * indent_delta, "", TEEP_OPTIONS_KEY_HAVE_BINARY, (query_response->requested_tc_list.items[i].have_binary) ? "true" : "false");
            }
            printf("\n%*s}\n", indent_space + 3 * indent_delta, "");
        }
        printf("%*s]", indent_space + 2 * indent_delta, "");
    }
    if (query_response->contains & TEEP_MESSAGE_CONTAINS_UNNEEDED_TC_LIST) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ unneeded-tc-list / %d : [\n", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_UNNEEDED_TC_LIST);
        for (size_t i = 0; i < query_response->unneeded_tc_list.len; i++) {
            printf("%*s", indent_space + 3 * indent_delta, "");
            result = teep_print_component_id(&query_response->unneeded_tc_list.items[i]);
            if (result != TEEP_SUCCESS) {
                return result;
            }
        }
        printf("\n%*s]", indent_space + 2 * indent_delta, "");
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
                             const unsigned char *ta_public_key)
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

        printf("%*s/ token / %d : ", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_TOKEN);
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
            suit_mechanism_t suit_mechanisms[SUIT_MAX_KEY_NUM] = {0};
            suit_err_t suit_result = suit_key_init_es256_public_key(ta_public_key, &suit_mechanisms[0].key);
            if (suit_result != SUIT_SUCCESS) {
                return TEEP_ERR_UNEXPECTED_ERROR;
            }
            suit_mechanisms[0].cose_tag = CBOR_TAG_COSE_SIGN1;
            suit_mechanisms[0].use = true;

            suit_buf_t buf = {.ptr = (uint8_t *)teep_update->manifest_list.items[i].ptr, .len = teep_update->manifest_list.items[i].len};
            suit_envelope_t envelope = {0};
            suit_result = suit_decode_envelope(SUIT_DECODE_MODE_SKIP_ANY_ERROR, &buf, &envelope, suit_mechanisms);
            if (suit_result != SUIT_SUCCESS) {
                return TEEP_ERR_UNEXPECTED_ERROR;
            }

            printf("%*s<<\n", indent_space + 3 * indent_delta, "");
            suit_result = suit_print_envelope(SUIT_DECODE_MODE_SKIP_ANY_ERROR, &envelope, indent_space + 4 * indent_delta, indent_delta);
            if (suit_result != SUIT_SUCCESS) {
                return TEEP_ERR_UNEXPECTED_ERROR;
            }
            printf("\n%*s>>", indent_space + 3 * indent_delta, "");
#else
            printf("%*s", indent_space + 3 * indent_delta, "");
            result = teep_print_hex_within_max(teep_update->manifest_list.items[i].ptr, teep_update->manifest_list.items[i].len, TEEP_MAX_PRINT_BYTE_COUNT);
            if (result != TEEP_SUCCESS) {
                return result;
            }
#endif /* PARSE_SUIT */
            if (i + 1 < teep_update->manifest_list.len) {
                printf(",");
            }
            printf("\n");
        }
        printf("%*s]", indent_space + 2 * indent_delta, "");
    }
    if (teep_update->contains & TEEP_MESSAGE_CONTAINS_ATTESTATION_PAYLOAD_FORMAT) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ attestation-payload-format / %d : ", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_ATTESTATION_PAYLOAD_FORMAT);
        result = teep_print_string(&teep_update->attestation_payload_format);
        if (result != TEEP_SUCCESS) {
            return result;
        }
    }
    if (teep_update->contains & TEEP_MESSAGE_CONTAINS_ATTESTATION_PAYLOAD) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ attestation-payload / %d : ", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_ATTESTATION_PAYLOAD);
        result = teep_print_hex(teep_update->attestation_payload.ptr, teep_update->attestation_payload.len);
        if (result != TEEP_SUCCESS) {
            return result;
        }
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
        for (size_t i = 0; i < teep_error->supported_teep_cipher_suites.len; i++) {
            printf("%*s", indent_space + 3 * indent_delta, "");
            result = teep_print_cipher_suite(&teep_error->supported_teep_cipher_suites.items[i]);
            if (result != TEEP_SUCCESS) {
                return result;
            }
            printf(",\n");
        }
        printf("%*s]", indent_space + 2 * indent_delta, "");
    }
    /*
    if (teep_error->contains & TEEP_MESSAGE_CONTAINS_SUPPORTED_SUIT_COSE_PROFILES) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ supported-suit-cose-profiles / %d : [\n", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_SUPPORTED_SUIT_COSE_PROFILES);
        for (size_t i = 0; i < teep_error->supported_teep_cipher_suites.len; i++) {
            printf("%*s", indent_space + 3 * indent_delta, "");
            result = teep_print_cipher_suite(&teep_error->supported_teep_cipher_suites.items[i]);
            if (result != TEEP_SUCCESS) {
                return result;
            }
            printf(",\n");
        }
        printf("%*s]", indent_space + 2 * indent_delta, "");
    }
    */
    if (teep_error->contains & TEEP_MESSAGE_CONTAINS_SUPPORTED_FRESHNESS_MECHANISMS) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ supported-freshness-mechanisms / %d : [ ", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_SUPPORTED_FRESHNESS_MECHANISMS);
        for (size_t i = 0; i < teep_error->supported_freshness_mechanisms.len; i++) {
            printf("%u, ", teep_error->supported_freshness_mechanisms.items[i]);
        }
        printf("]");
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
    if (teep_error->contains & TEEP_MESSAGE_CONTAINS_SUIT_REPORTS) {
        if (printed) {
            printf(",\n");
        }
        printed = true;

        printf("%*s/ suit-reports / %d : [\n", indent_space + 2 * indent_delta, "", TEEP_OPTIONS_KEY_SUIT_REPORTS);
        for (size_t i = 0; i < teep_error->suit_reports.len; i++) {
            printf("%*s", indent_space + 3 * indent_delta, "");
            teep_print_hex(teep_error->suit_reports.items[i].ptr, teep_error->suit_reports.items[i].len);
            if (i + 1 < teep_error->suit_reports.len) {
                printf(",\n");
            }
        }
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
                              const unsigned char *ta_public_key)
{
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

char* teep_position_label_to_str(const int64_t position, const int64_t type)
{
    switch (position) {
    case 0: return "type";
    case 1: return "options";
    case 2:
        if (type == TEEP_TYPE_QUERY_REQUEST) {
            return "supported-teep-cipher-suites";
        }
        else if (type == TEEP_TYPE_TEEP_ERROR) {
            return "err-code";
        }
        break;
    case 3:
        if (type == TEEP_TYPE_QUERY_REQUEST) {
            return "supported-suit-cose-profiles";
        }
        break;
    case 4:
        if (type == TEEP_TYPE_QUERY_REQUEST) {
            return "data-item-requested";
        }
    }
    return NULL;
}

char* teep_position_label_to_str_sentinel(const int64_t position, const int64_t type)
{
    return NULL;
}

char* teep_message_type_to_str(const int64_t type, const int64_t n)
{
    switch (type) {
    case TEEP_TYPE_QUERY_REQUEST: return "TEEP-TYPE-QueryRequest";
    case TEEP_TYPE_QUERY_RESPONSE: return "TEEP-TYPE-QueryResponse";
    case TEEP_TYPE_UPDATE: return "TEEP-TYPE-Update";
    case TEEP_TYPE_TEEP_SUCCESS: return "TEEP-TYPE-Success";
    case TEEP_TYPE_TEEP_ERROR: return "TEEP-TYPE-Error";
    default: return NULL;
    }
}

char* teep_options_key_to_str(const int64_t label, const int64_t n)
{
    switch (label) {
    case TEEP_OPTIONS_KEY_INVALID: return "invalid";
    case TEEP_OPTIONS_KEY_SUPPORTED_TEEP_CIPHER_SUITES: return "supported-teep-cipher-suites";
    case TEEP_OPTIONS_KEY_CHALLENGE: return "challenge";
    case TEEP_OPTIONS_KEY_VERSIONS: return "versions";
    case TEEP_OPTIONS_KEY_SUPPORTED_SUIT_COSE_PROFILES: return "supported-suit-cose-profiles";
    case TEEP_OPTIONS_KEY_SELECTED_TEEP_CIPHER_SUITE: return "selected-teep-cipher-suite";
    case TEEP_OPTIONS_KEY_SELECTED_VERSION: return "selected-version";
    case TEEP_OPTIONS_KEY_ATTESTATION_PAYLOAD: return "attestation-payload";
    case TEEP_OPTIONS_KEY_TC_LIST: return "tc-list";
    case TEEP_OPTIONS_KEY_EXT_LIST: return "ext-list";
    case TEEP_OPTIONS_KEY_MANIFEST_LIST: return "manifest-list";
    case TEEP_OPTIONS_KEY_MSG: return "msg";
    case TEEP_OPTIONS_KEY_ERR_MSG: return "err-msg";
    case TEEP_OPTIONS_KEY_ATTESTATION_PAYLOAD_FORMAT: return "attestation-payload-format";
    case TEEP_OPTIONS_KEY_REQUESTED_TC_LIST: return "requested-tc-list";
    case TEEP_OPTIONS_KEY_UNNEEDED_TC_LIST: return "unneeded-tc-list";
    case TEEP_OPTIONS_KEY_COMPONENT_ID: return "component-id";
    case TEEP_OPTIONS_KEY_TC_MANIFEST_SEQUENCE_NUMBER: return "tc-manifest-sequence-number";
    case TEEP_OPTIONS_KEY_HAVE_BINARY: return "have-binary";
    case TEEP_OPTIONS_KEY_SUIT_REPORTS: return "suit-reports";
    case TEEP_OPTIONS_KEY_TOKEN: return "token";
    case TEEP_OPTIONS_KEY_SUPPORTED_FRESHNESS_MECHANISMS: return "supported-freshness-mechanisms";
    default: return NULL;
    }
}

char* teep_cose_header_label_to_str(const int64_t label, const int64_t n)
{
    switch (label) {
    case 1: return "alg";
    case 2: return "crit";
    case 3: return "content type";
    case 4: return "kid";
    case 5: return "IV";
    case 6: return "Partial IV";
    case 7: return "counter signature";
    default: return NULL;
    }
}


char* teep_eat_cnf_label_to_str(const int64_t label, const int64_t n)
{
    switch (label) {
    case 1: return "COSE_Key";
    case 2: return "Encrypted_COSE_Key";
    case 3: return "kid";
    default: return NULL;
    }
}

char* teep_eat_claim_label_to_str(const int64_t label, const int64_t n)
{
    switch (label) {
    case EAT_CLAIM_ISSUER: return "iss";
    case EAT_CLAIM_EXP: return "exp";
    case EAT_CLAIM_NOT_BEFORE: return "nbf";
    case EAT_CLAIM_TIMESTAMP: return "iat";
    case EAT_CLAIM_CONFIRMATION: return "cnf";
    case EAT_CLAIM_EAT_NONCE: return "eat_nonce";
    case EAT_CLAIM_SECURE_BOOT: return "secboot";
    case EAT_CLAIM_CHIP_VERSION: return "chip_version";
    case EAT_CLAIM_UEID: return "ueid";
    case EAT_CLAIM_SUEIDS: return "sueids";
    case EAT_CLAIM_OEMID: return "oemid";
    case EAT_CLAIM_HWMODEL: return "hwmodel";
    case EAT_CLAIM_HWVERSION: return "hwversion";
    case EAT_CLAIM_OEMBOOT: return "oemboot";
    case EAT_CLAIM_DBGSTAT: return "dbgstat";
    case EAT_CLAIM_LOCATION: return "location";
    case EAT_CLAIM_EAT_PROFILE: return "eat_profile";
    case EAT_CLAIM_SUBMODS: return "submods";
    case EAT_CLAIM_SWNAME: return "swname";
    case EAT_CLAIM_SWVERSION: return "swversion";
    case EAT_CLAIM_MANIFESTS: return "manifests";
    case EAT_CLAIM_MEASUREMENTS: return "measres";
    case EAT_CLAIM_VERIFIER_NONCE: return "verifier_nonce";
    default: return NULL;
    }
}

char* teep_eat_claim_label_to_str_sentinel(const int64_t label, const int64_t n)
{
    return NULL;
}

char* teep_position_cipher_suite_items(const int64_t position, const int64_t n)
{
    switch (position) {
    case 0: return "mechanism";
    case 1: return "algorithm-id";
    default: return NULL;
    }
}

char* teep_position_cipher_suite(const int64_t position, const int64_t n)
{
    return NULL;
}

char* teep_position_cipher_suites(const int64_t position, const int64_t n)
{
    return NULL;
}

char* teep_position_tc_list_to_str(const int64_t position, const int64_t n)
{
    return NULL;
}

char* suit_system_property_claims_to_str(const int64_t label, const int64_t n)
{
    switch (label) {
    case 0: return "system-component-id";
#if PARSE_SUIT
    default: return (char *)suit_parameter_key_to_str(label);
#else
    default: return NULL;
#endif
    }
}

char* teep_position_requested_tc_list_to_str(const int64_t position, const int64_t n)
{
    return NULL;
}

char* teep_debug_to_str(TeepLabelToStr from)
{
    if (teep_position_requested_tc_list_to_str == from) {
        return "position_requested_tc_list";
    }
    if (teep_eat_claim_label_to_str == from) {
        return "eat_claim_label";
    }
    if (teep_eat_claim_label_to_str_sentinel == from) {
        return "eat_claim_label_sentinel";
    }
    if (teep_cose_header_label_to_str == from) {
        return "cose_header_label";
    }
    if (teep_options_key_to_str == from) {
        return "teep_options_key";
    }
    if (teep_message_type_to_str == from) {
        return "message_type";
    }
    if (teep_position_label_to_str == from) {
        return "position";
    }
    return NULL;
}

TeepLabelToStr teep_a_to_str(TeepLabelToStr from, bool is_map, const int64_t label)
{
    if (from == teep_eat_claim_label_to_str_sentinel) {
        return teep_eat_claim_label_to_str;
    }
    else if (from == teep_position_label_to_str) {
        if (is_map) {
            return teep_options_key_to_str;
        }
        else {
            switch (label) {
            case 2: return teep_position_cipher_suites;
            case 3: return NULL; /* TODO: teep_position_profiles */
            }
        }
    }
    else if (from == teep_eat_claim_label_to_str) {
        switch (label) {
        case EAT_CLAIM_CONFIRMATION:
            return teep_eat_cnf_label_to_str;
        }
    }
    else if (from == teep_position_label_to_str) {
        return teep_options_key_to_str;
    }
    else if (from == teep_position_tc_list_to_str) {
        return suit_system_property_claims_to_str;
    }
    else if (from == teep_position_requested_tc_list_to_str) {
        return teep_options_key_to_str;
    }
    else if (from == teep_position_label_to_str_sentinel) {
        return teep_position_label_to_str;
    }
    else if (from == teep_options_key_to_str) {
        switch (label) {
        case TEEP_OPTIONS_KEY_TC_LIST:
            return teep_position_tc_list_to_str;
        case TEEP_OPTIONS_KEY_REQUESTED_TC_LIST:
            return teep_position_requested_tc_list_to_str;
        case TEEP_OPTIONS_KEY_SELECTED_TEEP_CIPHER_SUITE:
            return teep_position_cipher_suite;
        }
    }
    else if (from == teep_position_cipher_suite) {
        return teep_position_cipher_suite_items;
    }
    else if (from == teep_position_cipher_suites) {
        return teep_position_cipher_suite;
    }
    return NULL;
}

char* teep_cose_tag_to_str(void *type)
{
    return teep_cose_mechanism_key_to_str(*(int64_t *)type);
}

char* teep_algorithm_id_to_str(void *type)
{
    return teep_cose_algs_key_to_str(*(int64_t *)type);
}

char* teep_message_type_value_to_str(void *type)
{
    return teep_message_type_to_str(*(int64_t *)type, 0);
}

static char buf[32];
char* teep_data_item_requested_to_str(void *type)
{
    size_t len = 0;
    teep_data_item_requested_t r;
    r.val = *(int64_t *)type;

    if (r.attestation) {
        len += sprintf(&buf[len], "attestation|");
    }
    if (r.trusted_components) {
        len += sprintf(&buf[len], "trusted-components|");
    }
    if (r.extensions) {
        len += sprintf(&buf[len], "extensions");
    }
    if (len > 0) {
        buf[len - 1] = '\0';
        return buf;
    }
    return NULL;
}

char* teep_alg_id_to_str(void *id)
{
    return teep_cose_algs_key_to_str(*(int64_t *)id);
}

TeepPrintValue teep_value_to_str(TeepLabelToStr f, int64_t n)
{
    if (teep_position_label_to_str == f) {
        switch (n) {
        case 0: return teep_message_type_value_to_str;
        case 4: return teep_data_item_requested_to_str;
        }
    }
    else if (teep_cose_header_label_to_str == f) {
        switch (n) {
        case 1: return teep_alg_id_to_str;
        }
    }
    else if (teep_position_cipher_suite_items == f) {
        switch (n) {
        case 0: return teep_cose_tag_to_str;
        case 1: return teep_algorithm_id_to_str;
        }
    }

    return NULL;
}

char* teep_debug_to_print(TeepPrintValue from)
{
    if (teep_message_type_value_to_str == from) {
        return "message_type";
    }
    else if (teep_data_item_requested_to_str == from) {
        return "data_item_requested";
    }
    else if (teep_alg_id_to_str == from) {
        return "alg_id";
    }
    else if (teep_cose_tag_to_str == from) {
        return "cose_tag";
    }
    else if (teep_algorithm_id_to_str == from) {
        return "algorithm_id";
    }
    return NULL;
}

void teep_print_value(QCBORDecodeContext *context,
                 QCBORItem *item,
                 const uint32_t indent_space,
                 const uint32_t indent_delta,
                 TeepLabelToStr label_to_str,
                 const int64_t label,
                 bool in_header)
{
    union {
        int64_t int64;
        uint64_t uint64;
        UsefulBufC string;
        bool boolean;
    } val;

    switch (item->uDataType) {
    case QCBOR_TYPE_INT64:
        QCBORDecode_GetInt64(context, &val.int64);
        printf("%ld", val.int64);
        break;
    case QCBOR_TYPE_UINT64:
        QCBORDecode_GetUInt64(context, &val.uint64);
        printf("%ld", val.uint64);
        break;
    case QCBOR_TYPE_ARRAY:
        QCBORDecode_EnterArray(context, item);
        teep_print_array(context, item, indent_space, indent_delta, label_to_str, label, in_header);
        QCBORDecode_ExitArray(context);
        break;
    case QCBOR_TYPE_MAP:
        QCBORDecode_EnterMap(context, item);
        teep_print_map(context, item, indent_space, indent_delta, label_to_str, label, in_header);
        QCBORDecode_ExitMap(context);
        break;
    case QCBOR_TYPE_BYTE_STRING:
        QCBORDecode_GetByteString(context, &val.string);
        teep_print_hex_within_max(val.string.ptr, val.string.len, TEEP_MAX_PRINT_BYTE_COUNT);
        break;
    case QCBOR_TYPE_TEXT_STRING:
        QCBORDecode_GetTextString(context, &val.string);
        teep_print_text(val.string.ptr, item->val.string.len);
        break;
    case QCBOR_TYPE_TRUE:
        QCBORDecode_GetBool(context, &val.boolean);
        printf("true");
        break;
    case QCBOR_TYPE_FALSE:
        QCBORDecode_GetBool(context, &val.boolean);
        printf("false");
        break;
    case QCBOR_TYPE_NULL:
        QCBORDecode_GetNull(context);
        printf("null");
        break;
    }

    TeepPrintValue f = teep_value_to_str(label_to_str, label);
    if (f != NULL && f(&val) != NULL) {
        /* there is something to print for the value */
        printf(" / %s /", f(&val));
    }
}

void teep_print_map(QCBORDecodeContext *context,
               QCBORItem *item,
               const uint32_t indent_space,
               const uint32_t indent_delta,
               TeepLabelToStr label_to_str,
               const int64_t label,
               bool in_header)
{
    printf("{\n");
    size_t length = item->val.uCount;
    for (size_t i = 0; i < length; i++) {
        QCBORDecode_PeekNext(context, item);
        TeepLabelToStr tmp_label_to_str = label_to_str;
        if (item->uDataType == QCBOR_TYPE_ARRAY) {
            tmp_label_to_str = teep_a_to_str(label_to_str, false, item->label.int64);
        }
        else if (item->uDataType == QCBOR_TYPE_MAP) {
            tmp_label_to_str = teep_a_to_str(label_to_str, true, item->label.int64);
        }
        printf("%*s", indent_space + indent_delta, "");
        if (label_to_str != NULL) {
            printf("/ %s / ",  label_to_str(item->label.int64, item->label.int64));
        }
        printf("%ld : ", item->label.int64);

        teep_print_value(context, item, indent_space + indent_delta, indent_delta, tmp_label_to_str, item->label.int64, in_header);

        if (i + 1 < length) {
            printf(",");
        }
        printf("\n");
    }
    printf("%*s}", indent_space, "");
}

void teep_print_array(QCBORDecodeContext *context,
                 QCBORItem *item,
                 const uint32_t indent_space,
                 const uint32_t indent_delta,
                 TeepLabelToStr position_to_str,
                 const int64_t position,
                 bool in_header)
{
    size_t length = item->val.uCount;

    int64_t type = 0;
    bool is_teep_protocol = position_to_str == teep_position_label_to_str;
    if (is_teep_protocol) {
        QCBORDecode_PeekNext(context, item);
        type = item->val.int64;
    }
    bool is_inline = (position_to_str == NULL);
    bool has_label = (is_inline) ? false : position_to_str(0, type) != NULL;
    printf("[%c", is_inline ? ' ' : '\n');

    int64_t prev_label = item->label.int64;
    for (size_t i = 0; i < length; i++) {
        QCBORDecode_PeekNext(context, item);
        TeepLabelToStr tmp_position_to_str = position_to_str;
        if (item->uDataType == QCBOR_TYPE_ARRAY) {
            tmp_position_to_str = teep_a_to_str(position_to_str, false, i);
        }
        else if (item->uDataType == QCBOR_TYPE_MAP) {
            tmp_position_to_str = teep_a_to_str(position_to_str, true, prev_label);
        }

        if (!is_inline) {
            printf("%*s", indent_space + indent_delta, "");
        }
        if (has_label) {
            printf("/ %s: / ", position_to_str(i, type));
        }

        teep_print_value(context, item, indent_space + indent_delta, indent_delta, tmp_position_to_str, i, in_header);

        if (i + 1 < length) {
            printf(",");
            printf("%c", (position_to_str == NULL) ? ' ' : '\n');
        }
    }

    if (is_inline) {
        printf(" ]");
    }
    else {
        printf("\n%*s]", indent_space, "");
    }
}

teep_err_t teep_print_cose_header(QCBORDecodeContext *context,
                                   const uint32_t indent_space,
                                   const uint32_t indent_delta)
{
    QCBORItem item;
    QCBORDecode_EnterMap(context, &item);
    teep_print_map(context, &item, indent_space, indent_delta, teep_cose_header_label_to_str, false, true);
    QCBORDecode_ExitMap(context);
    return TEEP_SUCCESS;
}

teep_err_t teep_print_cose(QCBORDecodeContext *context,
                            const uint32_t indent_space,
                            const uint32_t indent_delta,
                            TeepLabelToStr label_to_str)
{
    QCBORItem item;

    printf("%*s", indent_space, "");
    uint16_t cose_tag = 0;
    item.uTags[0] = 0;
    QCBORDecode_EnterArray(context, &item);
    if (QCBORDecode_GetError(context) != QCBOR_SUCCESS) {
        printf("context.uLastError = %d\n", QCBORDecode_GetError(context));
        return TEEP_ERR_FATAL;
    }
    if (item.uTags[0] != 0) {
        cose_tag = item.uTags[0];
        printf("%d(", cose_tag);
    }
    if (item.val.uCount != 4) {
        printf("item.val.uCount = %d\n", item.val.uCount);
        return TEEP_ERR_FATAL;
    }

    QCBORDecode_EnterBstrWrapped(context, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
    printf("[\n%*s/ protected: / << ", indent_space + indent_delta, "");
    teep_print_cose_header(context, indent_space + indent_delta, indent_delta);
    printf(" >>,\n");
    QCBORDecode_ExitBstrWrapped(context);
    printf("%*s/ unprotected: / ", indent_space + indent_delta, "");
    teep_print_cose_header(context, indent_space + indent_delta, indent_delta);
    printf(",\n");

    printf("%*s/ payload: / << ", indent_space + indent_delta, "");
    QCBORDecode_EnterBstrWrapped(context, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
    QCBORDecode_PeekNext(context, &item);
    teep_print_value(context, &item, indent_space + indent_delta, indent_delta, label_to_str, 0, false);
    QCBORDecode_ExitBstrWrapped(context);
    printf(" >>,\n");

    printf("%*s/ signature: / ", indent_space + indent_delta, "");
    UsefulBufC signature;
    QCBORDecode_GetByteString(context, &signature);
    teep_print_hex(signature.ptr, signature.len);

    QCBORDecode_ExitArray(context);
    printf("\n]");

    if (cose_tag != 0) {
        printf(")");
    }
    printf("\n");

    return TEEP_SUCCESS;
}

teep_err_t teep_print_cose_usefulbufc(UsefulBufC cose,
                           const uint32_t indent_space,
                           const uint32_t indent_delta,
                           TeepLabelToStr label_to_str)
{
    QCBORDecodeContext context;
    QCBORDecode_Init(&context, cose, QCBOR_DECODE_MODE_NORMAL);

    teep_err_t result = teep_print_cose(&context, indent_space, indent_delta, label_to_str);

    QCBORError qcbor_err = QCBORDecode_Finish(&context);
    if (qcbor_err != QCBOR_SUCCESS) {
        printf("qcbor_err = %u\n", qcbor_err);
        return TEEP_ERR_FATAL;
    }
    return result;
}

teep_err_t teep_print_cose_eat(UsefulBufC cose_eat,
                           const uint32_t indent_space,
                           const uint32_t indent_delta)
{
    return teep_print_cose_usefulbufc(cose_eat, indent_space, indent_delta, teep_eat_claim_label_to_str);
}

teep_err_t teep_print_cose_teep_message(UsefulBufC cose_teep_message,
                           const uint32_t indent_space,
                           const uint32_t indent_delta)
{
    return teep_print_cose_usefulbufc(cose_teep_message, indent_space, indent_delta, teep_position_label_to_str);
}
