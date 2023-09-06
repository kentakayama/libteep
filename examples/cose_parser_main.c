/*
 * Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include "teep/teep_message_print.h"
#include "teep_examples_common.h"

int main(int argc, const char *argv[])
{
    const char *cose_file_name = NULL;

    if (argc < 2) {
        printf("%s <COSE file path>\n", argv[0]);
        return EXIT_FAILURE;
    }
    cose_file_name = argv[1];

    // Read cose file.
    UsefulBuf_MAKE_STACK_UB(cose_buf, 1024);

    printf("main : Read CBOR file.\n");
    cose_buf.len = read_from_file(cose_file_name, cose_buf.ptr, 1024);
    if (cose_buf.len == 0) {
        printf("main : Failed to read CBOR file.\n");
        return EXIT_FAILURE;
    }
    teep_print_hex_within_max(cose_buf.ptr, cose_buf.len, 1024);
    printf("\n");

    // Print cose file.
    printf("main : Print COSE file.\n");
    teep_print_cose_eat(UsefulBuf_Const(cose_buf), 4, 2);

    return EXIT_SUCCESS;
}
