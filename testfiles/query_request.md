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
  / supported-eat-suit-cipher-suites: / [
    [ [ 18, -7 ] ] / Sign1 using ES256 /
  ],
  / data-item-requested: / 3 / attestation | trusted-components /
]
~~~~


## CBOR binary Representation
~~~~
85                  # array(5)
   01               # unsigned(1) / TEEP-TYPE-query-request /
   A2               # map(2)
      14            # unsigned(20) / token: /
      50            # bytes(16)
         A0A1A2A3A4A5A6A7A8A9AAABACADAEAF
      03            # unsigned(3) / versions: /
      81            # array(1) / [ 0 ] /
         00         # unsigned(0)
   82               # array(2)      / supported-teep-cipher-suites: /
      81            # array(1)
         82         # array(2)
            12      # unsigned(18)  / 18 = COSE_Sign1 /
            26      # negative(6)   / -7 = cose-alg-es256 /
      81            # array(1)
         82         # array(2)
            12      # unsigned(18)  / 18 = COSE_Sign1 /
            27      # negative(7)   / -8 = cose-alg-eddsa /
   81               # array(1)      / supported-eat-suit-cipher-suites: /
      81            # array(1)
         82         # array(2)
            12      # unsigned(18) / 18 = COSE_Sign1 /
            27      # negative(7) / -8 = cose-alg-eddsa /

   03               # unsigned(3) / attestation | trusted-components /
~~~~
