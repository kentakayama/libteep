/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef TEEP_MESSAGE_PRINT_H
#define TEEP_MESSAGE_PRINT_H

#include <stdio.h>
#include "qcbor/qcbor.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "teep_common.h"
#include "teep_message_data.h"

#define TEEP_MAX_PRINT_BYTE_COUNT       64
#define TEEP_MAX_PRINT_TEXT_COUNT       16

const char *teep_err_to_str(teep_err_t err);
const char *teep_err_code_to_str(int32_t err_code);
const char *teep_cose_algs_key_to_str(int64_t cose_algs_key);
teep_err_t teep_print_query_request(const teep_query_request_t *query_request, uint32_t indent_space, uint32_t indent_delta);
teep_err_t teep_print_query_response(const teep_query_response_t *query_response, uint32_t indent_space, uint32_t indent_delta);
teep_err_t teep_print_update(const teep_update_t *teep_update, uint32_t indent_space, uint32_t indent_delta, const unsigned char *ta_public_key);
teep_err_t teep_print_success(const teep_success_t *success, uint32_t indent_space, uint32_t indent_delta);
teep_err_t teep_print_error(const teep_error_t *error, uint32_t indent_space, uint32_t indent_delta);
teep_err_t teep_print_message(const teep_message_t *msg, uint32_t indent_space, uint32_t indent_delta, const unsigned char *ta_public_key);

const char* teep_eat_claim_label_to_str(const int64_t label, const int64_t n);
const char* teep_position_to_str(const int64_t label, const int64_t type);

void teep_print_map(QCBORDecodeContext *context,
               QCBORItem *item,
               const uint32_t indent_space,
               const uint32_t indent_delta,
               const char* (*label_to_str)(int64_t, int64_t),
               const int64_t label,
               bool in_header);
void teep_print_array(QCBORDecodeContext *context,
                 QCBORItem *item,
                 const uint32_t indent_space,
                 const uint32_t indent_delta,
                 const char* (*label_to_str)(int64_t, int64_t),
                 const int64_t position,
                 bool in_hdeader);

teep_err_t teep_print_cose_usefulbufc(UsefulBufC cose,
                                        const uint32_t indent_space,
                                        const uint32_t indent_delta,
                                        const char* (*label_to_str)(int64_t, int64_t));
teep_err_t teep_print_cose_eat(UsefulBufC cose_eat,
                           const uint32_t indent_space,
                           const uint32_t indent_delta);
teep_err_t teep_print_cose_teep_message(UsefulBufC cose_teep_message,
                           const uint32_t indent_space,
                           const uint32_t indent_delta);

#endif  /* TEEP_MESSAGE_PRINT_H */
