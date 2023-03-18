<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# QueryRequest Message
    https://datatracker.ietf.org/doc/html/draft-ietf-teep-protocol-12#name-d3-queryresponse-message

## CBOR Diagnostic Notation
~~~~cbor-diag
/ query-response = /
[
  / type: / 2 / TEEP-TYPE-query-response /,
  / options: /
  {
    / token / 20 : h'A0A1A2A3A4A5A6A7A8A9AAABACADAEAF',
    / selected-teep-cipher-suite / 5 : [ [ 18, -7 ] ] / Sign1 using ES256 /,
    / selected-version / 6 : 0,
    / tc-list / 8 : [
      {
        / system-component-id / 0 : [ h'0102030405060708090A0B0C0D0E0F' ],
        / suit-parameter-image-digest / 3 : << [
          / suit-digest-algorithm-id / -16 / SHA256 /,
          / suit-digest-bytes / h'A7FD6593EAC32EB4BE578278E6540C5C09CFD7D4D234973054833B2B93030609'
            / SHA256 digest of tc binary /
        ] >>
      },
      {
        / system-component-id / 0 : [ h'1102030405060708090A0B0C0D0E0F' ],
        / suit-parameter-version / 28 : [ 1, 0, 0 ] / ver 1.0.0 /
      }
    ]
  }
]
~~~~


## CBOR binary Representation
~~~~
82                      # array(2)
   02                   # unsigned(2) / TEEP-TYPE-query-response /
   A4                   # map(4)
      14                # unsigned(20) / token: /
      50                # bytes(16)
         A0A1A2A3A4A5A6A7A8A9AAABACADAEAF
      05                # unsigned(5) / selected-cipher-suite: /
      81                # array(1)
         82             # array(2)
            12          # unsigned(18) / 18 = COSE_Sign1 /
            26          # negative(6) / -7 = cose-alg-es256 /
      06                # unsigned(6) / selected-version: /
      00                # unsigned(0)
      08                # unsigned(8) / tc-list: /
      82                # array(2)
         A2             # map(2)
            00          # unsigned(0) / system-component-id: /
            81          # array(1)
               4F       # bytes(15)
                  0102030405060708090A0B0C0D0E0F
            03          # unsigned(3) / suit-parameter-image-digest: /
            58 24       # bytes(36)
               82       # array(2)
                  2F    # negative(15) / -16 = cose-alg-sha256 /
                  58 20 # bytes(32)
                     A7FD6593EAC32EB4BE578278E6540C5C09CFD7D4D234973054833B2B93030609
         A1             # map(1)
            00          # unsigned(0) / system-component-id: /
            81          # array(1)
               4F       # bytes(15)
                  1102030405060708090A0B0C0D0E0F
            18 1C       # unsigned(28) / suit-parameter-version: /
            83          # array(3) / 1.0.0 /
               01       # unsigned(1)
               00       # unsigned(0)
               00       # unsigned(0)
~~~~
