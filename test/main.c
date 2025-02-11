/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "teep/teep.h"
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <string.h>

void test_set_out_of_teep_buf(void);
void test_add_usefulbufc(void);

int main(int argc, char *argv[])
{
    CU_pSuite suite;
    CU_initialize_registry();
    suite = CU_add_suite("TEEP", NULL, NULL);
    CU_add_test(suite, "test_set_out_of_teep_buf", test_set_out_of_teep_buf);
    CU_add_test(suite, "test_add_usefulbufc", test_add_usefulbufc);
    CU_basic_set_mode(CU_BRM_SILENT);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}

void test_add_usefulbufc(void)
{
    uint8_t component_id_bin[] = {0x81, 0x41, 0x00}; // [h'00']
    UsefulBufC component_id = (UsefulBufC){
        .ptr = component_id_bin,
        .len = sizeof(component_id_bin)
    };

    UsefulBuf_MAKE_STACK_UB(buf, 16);
    QCBOREncodeContext context;
    QCBOREncode_Init(&context, buf);

    QCBOREncode_OpenMap(&context);
    teep_QCBOREncode_AddUsefulBufCToMapN(&context, 16, component_id);
    QCBOREncode_CloseMap(&context);
    UsefulBufC res;
    QCBOREncode_Finish(&context, &res);

    uint8_t to_be_bin[] = {0xa1, 0x10, 0x81, 0x41, 0x00}; // {16: [h'00']}
    UsefulBufC to_be = (UsefulBufC){
        .ptr = to_be_bin,
        .len = sizeof(to_be_bin)
    };

    CU_ASSERT(res.len == to_be.len);
    CU_ASSERT(memcmp((void *)res.ptr, to_be.ptr, res.len) == 0);
}

void test_set_out_of_teep_buf_from_buf(uint8_t *ptr,
                                       size_t len,
                                       teep_buf_t *buf)
{
    QCBORDecodeContext context;
    QCBORItem item;
    QCBORError error;
    QCBORDecode_Init(&context, (UsefulBufC){ptr, len}, QCBOR_DECODE_MODE_NORMAL);
    error = QCBORDecode_GetNext(&context, &item);
    CU_ASSERT(error == QCBOR_SUCCESS);
    int32_t result = teep_set_out_of_teep_buf(&context, &item, buf);
    CU_ASSERT(result == TEEP_SUCCESS);
    error = QCBORDecode_Finish(&context);
    CU_ASSERT(error == QCBOR_SUCCESS);
    return;
}

void test_set_out_of_teep_buf(void)
{
    teep_buf_t teep_buf;

    /* SUIT_Envelope as .cbor bstr */
    uint8_t buf0[] = {0x81, 0x46, 0xA2, 0x02, 0x80, 0x03, 0x41, 0xA0};
    test_set_out_of_teep_buf_from_buf(buf0, sizeof(buf0), &teep_buf);
    CU_ASSERT(teep_buf.len == sizeof(buf0));
    CU_ASSERT(teep_buf.ptr == buf0);

    /* SUIT_Component_Identifier as Array of Array of bstr */
    uint8_t buf1[] = {0x83, 0x81, 0x41, 0x00, 0x81, 0x41, 0x02, 0x81, 0x41, 0x01};
    test_set_out_of_teep_buf_from_buf(buf1, sizeof(buf1), &teep_buf);
    CU_ASSERT(teep_buf.len == sizeof(buf1));
    CU_ASSERT(teep_buf.ptr == buf1);
}


