<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# QueryRequest Message
    https://datatracker.ietf.org/doc/html/draft-ietf-teep-protocol-12#name-d1-queryrequest-message

## CBOR Diagnostic Notation
~~~~cbor-diag
/ query-request = /
[
  / type: / 1 / TEEP-TYPE-query-request /,
  / options: /
  {
    / token / 20 : h'A0A1A2A3A4A5A6A7A8A9AAABACADAEAF',
    / versions / 3 : [ 0 ]  / 0 is current TEEP Protocol /
  },
  / supported-teep-cipher-suites: / [
    [ [ 18, -7 ] ], / Sign1 using ES256 /
    [ [ 18, -8 ] ]  / Sign1 using EdDSA /
  ],
  / supported-suit-cose-profiles: / [
    [ -16, -7, -25, -65534 ] / suit-sha256-es256-ecdh-a128ctr /,
    [ -16, -8, -25, -65534 ] / suit-sha256-eddsa-ecdh-a128ctr /
  ],
  / data-item-requested: / 3 / attestation | trusted-components /
]
~~~~


## CBOR binary Representation
~~~~
85                  # array(5)
   01               # unsigned(1)     / TEEP-TYPE-query-request /
   A2               # map(2)
      14            # unsigned(20)    / token: /
      50            # bytes(16)
         A0A1A2A3A4A5A6A7A8A9AAABACADAEAF
      03            # unsigned(3)     / versions: /
      81            # array(1) / [ 0 ] /
         00         # unsigned(0)
   82               # array(2)        / supported-teep-cipher-suites: /
      81            # array(1)
         82         # array(2)
            12      # unsigned(18)    / 18 = COSE_Sign1 /
            26      # negative(6)     / -7 = cose-alg-es256 /
      81            # array(1)
         82         # array(2)
            12      # unsigned(18)    / 18 = COSE_Sign1 /
            27      # negative(7)     / -8 = cose-alg-eddsa /
   82               # array(2)        / supported-suit-cose-profiles: /
      84            # array(4)        / suit-sha256-es256-ecdh-a128ctr /
         2F         # negative(15)    / -16 = cose-alg-sha256 /
         26         # negative(6)     / -7 = cose-alg-es256 /
         38 18      # negative(24)    / -25 = cose-alg-ecdhes-hkdf256 /
         39 FFFD    # negative(65533) / -65534 = A128CTR /
      84            # array(4)        / suit-sha256-eddsa-ecdh-a128ctr /
         2F         # negative(15)    / -16 = cose-alg-sha256 /
         27         # negative(7)     / -8 = cose-alg-eddsa /
         38 18      # negative(24)    / -25 = cose-alg-ecdhes-hkdf256 /
         39 FFFD    # negative(65533) / -65534 = A128CTR /
   03               # unsigned(3)     / attestation | trusted-components /
~~~~
