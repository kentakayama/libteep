/*
 * Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

#ifndef VERIFIER_ES256_COSE_KEY_PUBLIC_H
#define VERIFIER_ES256_COSE_KEY_PUBLIC_H
const unsigned char verifier_es256_cose_key_public_buf[] = {
    0xA4,                                 //# map(4)
       0x01,                              //# unsigned(1) / 1 = kty /
       0x02,                              //# unsigned(2) / 2 = EC2 /
       0x20,                              //# negative(0) / -1 = crv /
       0x01,                              //# unsigned(1) / 1 = P-256 /
       0x21,                              //# negative(1) / -2 = x /
       0x58, 0x20,                        //# bytes(32)
          0x2A, 0xFB, 0x0A, 0xBC, 0x6A, 0x31, 0x86, 0x81,
          0x22, 0xE2, 0x53, 0x43, 0xB6, 0xB4, 0x5A, 0x5B,
          0x9B, 0xF0, 0xCC, 0xB9, 0x16, 0xA2, 0xDC, 0x22,
          0xA0, 0x07, 0x49, 0xFF, 0xF6, 0x92, 0x8E, 0x91,
       0x22,                              //# negative(2) / -3 = y /
       0x58, 0x20,                        //# bytes(32)
          0x3A, 0x26, 0x02, 0xC7, 0xE9, 0x5A, 0x55, 0xD4,
          0xB6, 0x9D, 0x82, 0xA1, 0x9A, 0x4A, 0xEE, 0x80,
          0x81, 0xE8, 0xCF, 0xE4, 0xC7, 0x71, 0x2F, 0x2F,
          0x06, 0x01, 0x0D, 0x75, 0xEC, 0x0C, 0x3D, 0x2F,
};
const UsefulBufC verifier_es256_cose_key_public = {
    .ptr = verifier_es256_cose_key_public_buf,
    .len = sizeof(verifier_es256_cose_key_public_buf)
};
#endif /* VERIFIER_ES256_COSE_KEY_PUBLIC_H */
