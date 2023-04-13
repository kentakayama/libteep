/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

#ifndef TEEP_EXAMPLES_COMMON_H
#define TEEP_EXAMPLES_COMMON_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

size_t read_from_file(const char *file_path,
                      uint8_t *buf,
                      const size_t buf_len);
size_t write_to_file(const char *file_path,
                     const void *buf,
                     const size_t buf_len);

#endif  /* TEEP_EXAMPLES_COMMON_H */
