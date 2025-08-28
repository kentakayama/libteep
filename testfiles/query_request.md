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
    [ -16, -7, -29, -65534 ] / suit-sha256-es256-ecdh-a128ctr /,
    [ -16, -8, -29, -65534 ] / suit-sha256-eddsa-ecdh-a128ctr /
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
         38 1C      # negative(28)    / -29 = cose-alg-ecdhes-a128kw /
         39 FFFD    # negative(65533) / -65534 = A128CTR /
      84            # array(4)        / suit-sha256-eddsa-ecdh-a128ctr /
         2F         # negative(15)    / -16 = cose-alg-sha256 /
         27         # negative(7)     / -8 = cose-alg-eddsa /
         38 1C      # negative(28)    / -29 = cose-alg-ecdhes-a128kw /
         39 FFFD    # negative(65533) / -65534 = A128CTR /
   03               # unsigned(3)     / attestation | trusted-components /
~~~~

## COSE_Sign protected QueryRequest Message in diag
~~~~
/ COSE_Sign_Tagged = / 98([
  / protected: / << {} >>,
  / unprotected: / {},
  / payload: / <<
    / query-request = / [
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
  >>,
  / signatures: / [
    [
      / protected: / << {
        / alg / 1: -7 / ES256 /
      } >>,
      / unprotected: / {
        / kid / 4: h'C770EC535D8C949586324ADAF2DDFFB76B1A852DFA52E19C80F7440EC163BEEA' / TAM's ES256 key /
      },
      / signature: / h'112E08A40567B08A1D4669DB9F0149A1DEA6D16B8FC1A3254654D6D40E2DC08BFB6F00DE2033A237454B537E2C55D55929E97A972FE807A930379BB1500473A6'
    ],
    [
      / protected: / << {
        / alg / 1: -8 / EdDSA /
      } >>,
      / unprotected: / {
        / kid / 4: h'866EEFBD6718C8846CD7DDFE43FC74AB1DAAC4538FF8514EA2EC2D410A415743' / TAM's EdDSA key /
      },
      / signature: / h'28CED0F30B7A0D1D797BD2CC10BE54D3E26126BE8C74E47EA868C5D96516A25AD28651C7F8B6A19704274E2258AA44E874BCA2D5D09C78A0019A4A15783B000F'
    ]
  ]
])
~~~~

- [TAM's ES256 key](../examples/inc/tam_es256_cose_key_public.h)
- [TAM's EdDSA key](../examples/inc/tam_ed25519_cose_key_public.h)
