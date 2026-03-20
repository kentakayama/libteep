/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef TEEP_HTTP_CLIENT_H
#define TEEP_HTTP_CLIENT_H

#include <curl/curl.h>
#include "teep/teep_common.h"

typedef enum teep_http_post_result {
    TEEP_HTTP_POST_OK = 0,
    TEEP_HTTP_POST_NO_CONTENT,
    TEEP_HTTP_POST_TRANSPORT_ERROR,
    TEEP_HTTP_POST_RESPONSE_ERROR,
} teep_http_post_result_t;

teep_http_post_result_t teep_send_http_post(const char *url,
                                            UsefulBufC send_buffer,
                                            UsefulBuf *recv_buffer);

#endif  // TEEP_HTTP_CLIENT_H
