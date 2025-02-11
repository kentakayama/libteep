/*
 * Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

#ifndef TEEP_AGENT_ES256_COSE_KEY_PUBLIC_H
#define TEEP_AGENT_ES256_COSE_KEY_PUBLIC_H
const unsigned char teep_agent_es256_cose_key_public_buf[] = {
    0xA4,                                 //# map(4)
       0x01,                              //# unsigned(1) / 1 = kty /
       0x02,                              //# unsigned(2) / 2 = EC2 /
       0x20,                              //# negative(0) / -1 = crv /
       0x01,                              //# unsigned(1) / 1 = P-256 /
       0x21,                              //# negative(1) / -2 = x /
       0x58, 0x20,                        //# bytes(32)
          0x58, 0x86, 0xCD, 0x61, 0xDD, 0x87, 0x58, 0x62,
          0xE5, 0xAA, 0xA8, 0x20, 0xE7, 0xA1, 0x52, 0x74,
          0xC9, 0x68, 0xA9, 0xBC, 0x96, 0x04, 0x8D, 0xDC,
          0xAC, 0xE3, 0x2F, 0x50, 0xC3, 0x65, 0x1B, 0xA3,
       0x22,                              //# negative(2) / -3 = y /
       0x58, 0x20,                        //# bytes(32)
          0x9E, 0xED, 0x81, 0x25, 0xE9, 0x32, 0xCD, 0x60,
          0xC0, 0xEA, 0xD3, 0x65, 0x0D, 0x0A, 0x48, 0x5C,
          0xF7, 0x26, 0xD3, 0x78, 0xD1, 0xB0, 0x16, 0xED,
          0x42, 0x98, 0xB2, 0x96, 0x1E, 0x25, 0x8F, 0x1B,
};
const UsefulBufC teep_agent_es256_cose_key_public = {
    .ptr = teep_agent_es256_cose_key_public_buf,
    .len = sizeof(teep_agent_es256_cose_key_public_buf)
};
#endif /* TEEP_AGENT_ES256_COSE_KEY_PUBLIC_H */
