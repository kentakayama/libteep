/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "teep_examples_common.h"

size_t read_from_file(const char *file_path,
                      uint8_t *buf,
                      const size_t buf_len)
{
    size_t read_len = 0;
    FILE* fp = fopen(file_path, "rb");
    if (fp == NULL) {
        return 0;
    }
    read_len = fread(buf, 1, buf_len, fp);
    fclose(fp);
    return read_len;
}

size_t write_to_file(const char *file_path,
                     const void *buf,
                     const size_t buf_len)
{
    size_t write_len = 0;
    FILE* fp = fopen(file_path, "wb");
    if (fp == NULL) {
        return 0;
    }
    write_len = fwrite(buf, 1, buf_len, fp);
    fclose(fp);
    return write_len;
}
