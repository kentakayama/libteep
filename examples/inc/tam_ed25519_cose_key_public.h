/*
 * Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

#ifndef TAM_ED25519_COSE_KEY_PUBLIC_H
#define TAM_ED25519_COSE_KEY_PUBLIC_H
const unsigned char tam_ed25519_cose_key_public_buf[] = {
    0xA3,                                   //# map(3)
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
};
const UsefulBufC tam_ed25519_cose_key_public = {
    .ptr = tam_ed25519_cose_key_public_buf,
    .len = sizeof(tam_ed25519_cose_key_public_buf)
};
#endif /* TAM_ED25519_COSE_KEY_PUBLIC_H */
