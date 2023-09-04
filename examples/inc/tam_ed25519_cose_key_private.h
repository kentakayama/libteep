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
          0x17, 0x27, 0x7E, 0x80, 0x62, 0xA1, 0xF6, 0xC1,
          0xD9, 0x46, 0x20, 0xC6, 0x95, 0x38, 0xB7, 0xEB,
          0x37, 0xDB, 0xCA, 0x3A, 0x80, 0x61, 0x82, 0xF4,
          0x66, 0x20, 0x21, 0x55, 0x98, 0x05, 0x28, 0xF6,
       0x23,                                //# negative(3) / -4 = d /
       0x58, 0x20,                          //# bytes(32)
          0x91, 0x94, 0xBB, 0x0F, 0x04, 0x21, 0xF4, 0x67,
          0xDB, 0xBA, 0xAF, 0x0E, 0xA0, 0x93, 0x4D, 0x0D,
          0x0B, 0x25, 0xC8, 0x5A, 0x40, 0xA8, 0x75, 0x57,
          0x78, 0x6C, 0x50, 0x77, 0xD3, 0x8B, 0x98, 0x82,
};
const UsefulBufC tam_ed25519_cose_key_private = {
    .ptr = tam_ed25519_cose_key_private_buf,
    .len = sizeof(tam_ed25519_cose_key_private_buf)
};
#endif /* TAM_ED25519_COSE_KEY_PRIVATE_H */
