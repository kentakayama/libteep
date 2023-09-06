/*
 * Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

#ifndef TAM_ED25519_COSE_KEY_PRIVATE_H
#define TAM_ED25519_COSE_KEY_PRIVATE_H
const unsigned char tam_ed25519_cose_key_private_buf[] = {
    0xA4,                                   //# map(4)
       0x01,                                //# unsigned(1) / 1 = kty /
       0x01,                                //# unsigned(1) / 1 = OKP /
       0x20,                                //# negative(0) / -1 = crv /
       0x06,                                //# unsigned(6) / 6 = Ed25519 /
       0x21,                                //# negative(1) / -2 = x /
       0x58, 0x20,                          //# bytes(32)
          0xD7, 0x5A, 0x98, 0x01, 0x82, 0xB1, 0x0A, 0xB7,
          0xD5, 0x4B, 0xFE, 0xD3, 0xC9, 0x64, 0x07, 0x3A,
          0x0E, 0xE1, 0x72, 0xF3, 0xDA, 0xA6, 0x23, 0x25,
          0xAF, 0x02, 0x1A, 0x68, 0xF7, 0x07, 0x51, 0x1A,
       0x23,                                //# negative(3) / -4 = d /
       0x58, 0x20,                          //# bytes(32)
          0x9D, 0x61, 0xB1, 0x9D, 0xEF, 0xFD, 0x5A, 0x60,
          0xBA, 0x84, 0x4A, 0xF4, 0x92, 0xEC, 0x2C, 0xC4,
          0x44, 0x49, 0xC5, 0x69, 0x7B, 0x32, 0x69, 0x19,
          0x70, 0x3B, 0xAC, 0x03, 0x1C, 0xAE, 0x7F, 0x60,
};
const UsefulBufC tam_ed25519_cose_key_private = {
    .ptr = tam_ed25519_cose_key_private_buf,
    .len = sizeof(tam_ed25519_cose_key_private_buf)
};
#endif /* TAM_ED25519_COSE_KEY_PRIVATE_H */
