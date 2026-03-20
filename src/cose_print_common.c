/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include "teep/teep_common.h"
#include "teep/teep_message_data.h"
#include "teep/teep_message_print.h"
#include "teep/claims.h"
#include "cose_print_common.h"

#ifdef PARSE_SUIT
#include "csuit/csuit.h"
#endif

typedef char* (*TeepPrintValue)(void *val);

void teep_print_map(QCBORDecodeContext *context,
                    QCBORItem *item,
                    const uint32_t indent_space,
                    const uint32_t indent_delta,
                    TeepLabelToStr label_to_str,
                    const int64_t label,
                    bool in_header);
void teep_print_array(QCBORDecodeContext *context,
                      QCBORItem *item,
                      const uint32_t indent_space,
                      const uint32_t indent_delta,
                      TeepLabelToStr position_to_str,
                      const int64_t position,
                      bool in_header);

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
    case TEEP_COSE_SHA256:
        return "SHA-256";
    case TEEP_COSE_MAC_HMAC256:
        return "HMAC-256";
    case TEEP_COSE_SIGN_ES256:
        return "ES256";
    case TEEP_COSE_SIGN_ESP256:
        return "ESP256";
    case TEEP_COSE_SIGN_EDDSA:
        return "EdDSA";
    case TEEP_COSE_SIGN_ED25519:
        return "Ed25519";
    case TEEP_COSE_SIGN_HSS_LMS:
        return "HSS-LMS";
    case TEEP_COSE_A128KW:
        return "A128KW";
    case TEEP_COSE_ECDHES_HKDF256:
        return "ECDH-ES+HKDF-256";
    case TEEP_COSE_ECDHES_A128KW:
        return "ECDH-ES+A128KW";
    case TEEP_COSE_ENCRYPT_A128_GCM:
        return "AES-GCM-128";
    case TEEP_COSE_ENCRYPT_A192_GCM:
        return "AES-GCM-192";
    case TEEP_COSE_ENCRYPT_A256_GCM:
        return "AES-GCM-256";
    case TEEP_COSE_ENCRYPT_ACCM_16_64_128:
        return "AES-CCM-16-64-128";
    case TEEP_COSE_ENCRYPT_CHACHA20_POLY1305:
        return "ChaCha20/Poly1305";
    default:
        return NULL;
    }
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
        else if (type == TEEP_TYPE_ERROR) {
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
    case TEEP_TYPE_SUCCESS: return "TEEP-TYPE-Success";
    case TEEP_TYPE_ERROR: return "TEEP-TYPE-Error";
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
    case TEEP_OPTIONS_KEY_SELECTED_VERSION: return "selected-version";
    case TEEP_OPTIONS_KEY_ATTESTATION_PAYLOAD: return "attestation-payload";
    case TEEP_OPTIONS_KEY_TC_LIST: return "tc-list";
    case TEEP_OPTIONS_KEY_EXT_LIST: return "ext-list";
    case TEEP_OPTIONS_KEY_MANIFEST_LIST: return "manifest-list";
    case TEEP_OPTIONS_KEY_MSG: return "msg";
    case TEEP_OPTIONS_KEY_ERR_MSG: return "err-msg";
    case TEEP_OPTIONS_KEY_ATTESTATION_PAYLOAD_FORMAT: return "attestation-payload-format";
    case TEEP_OPTIONS_KEY_REQUESTED_TC_LIST: return "requested-tc-list";
    case TEEP_OPTIONS_KEY_UNNEEDED_TC_LIST: return "unneeded-manifest-list";
    case TEEP_OPTIONS_KEY_COMPONENT_ID: return "component-id";
    case TEEP_OPTIONS_KEY_TC_MANIFEST_SEQUENCE_NUMBER: return "tc-manifest-sequence-number";
    case TEEP_OPTIONS_KEY_HAVE_BINARY: return "have-binary";
    case TEEP_OPTIONS_KEY_SUIT_REPORTS: return "suit-reports";
    case TEEP_OPTIONS_KEY_TOKEN: return "token";
    case TEEP_OPTIONS_KEY_SUPPORTED_FRESHNESS_MECHANISMS: return "supported-freshness-mechanisms";
    case TEEP_OPTIONS_KEY_ERR_LANG: return "err-lang";
    case TEEP_OPTIONS_KEY_ERR_CODE: return "err-code";
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
        switch (label) {
        case 2: return teep_position_cipher_suites;
        case 3: return NULL;
        }
    }
    else if (from == teep_eat_claim_label_to_str) {
        switch (label) {
        case EAT_CLAIM_CONFIRMATION:
            return teep_eat_cnf_label_to_str;
        }
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

void teep_print_value(QCBORDecodeContext *context,
                      QCBORItem *item,
                      const uint32_t indent_space,
                      const uint32_t indent_delta,
                      TeepLabelToStr label_to_str,
                      const int64_t label,
                      bool in_header)
{
    union teep_value_t {
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
    default:
        break;
    }

    TeepPrintValue f = teep_value_to_str(label_to_str, label);
    if (f != NULL && f(&val) != NULL) {
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
            printf("/ %s / ", label_to_str(item->label.int64, item->label.int64));
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
    bool has_label = (!is_inline && position_to_str(0, type) != NULL);
    printf("[%c", is_inline ? ' ' : '\n');

    int64_t prev_label = item->label.int64;
    (void)position;
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

    QCBORDecode_PeekNext(context, &item);
    if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
        UsefulBufC signature;
        printf("%*s/ signature: / ", indent_space + indent_delta, "");
        QCBORDecode_GetByteString(context, &signature);
        teep_print_hex(signature.ptr, signature.len);
    }
    else if (item.uDataType == QCBOR_TYPE_ARRAY) {
        QCBORDecode_EnterArray(context, &item);
        size_t array_len = item.val.uCount;
        printf("%*s/ signatures: / [\n", indent_space + indent_delta, "");
        for (size_t i = 0; i < array_len; i++) {
            UsefulBufC signature;
            QCBORDecode_EnterArray(context, &item);
            if (item.val.uCount != 3) {
                return TEEP_ERR_INVALID_LENGTH;
            }
            printf("%*s[\n", indent_space + 2 * indent_delta, "");
            QCBORDecode_EnterBstrWrapped(context, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
            printf("%*s/ protected: / << ", indent_space + 3 * indent_delta, "");
            teep_print_cose_header(context, indent_space + 3 * indent_delta, indent_delta);
            printf(" >>,\n");
            QCBORDecode_ExitBstrWrapped(context);
            printf("%*s/ unprotected: / ", indent_space + 3 * indent_delta, "");
            teep_print_cose_header(context, indent_space + 3 * indent_delta, indent_delta);
            printf(",\n");
            printf("%*s/ signature: / ", indent_space + 3 * indent_delta, "");
            QCBORDecode_GetByteString(context, &signature);
            teep_print_hex(signature.ptr, signature.len);
            printf("\n%*s]", indent_space + 2 * indent_delta, "");
            QCBORDecode_ExitArray(context);
            if (i + 1 < array_len) {
                printf(",");
            }
            printf("\n");
        }
        printf("%*s]", indent_space + indent_delta, "");
        QCBORDecode_ExitArray(context);
    }
    else {
        return TEEP_ERR_INVALID_TYPE_OF_VALUE;
    }

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
