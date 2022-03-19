<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# QueryRequest Message
    https://tools.ietf.org/html/draft-ietf-teep-protocol-08#appendix-D.1

## CBOR Diagnostic Notation
    / query-request = /
    [
      / type: / 1 / TEEP-TYPE-query-request = 1 /,
      / options: /
      {
        / token / 20 : h'A0A1A2A3A4A5A6A7A8A9AAABACADAEAF',
        / supported-cipher-suites / 1 : [ [ -7, null, null ] ]  / use only ES256 /,
        / versions / 3 : [ 0 ]  / 0 is current TEEP Protocol /
      },
      / data-item-requested: / 3 / attestation | trusted-components = 3 /
    ]


## CBOR binary Representation
    83                  # array(3)
       01               # unsigned(1)
       A3               # map(3)
          14            # unsigned(20)
          50            # bytes(16)
             A0A1A2A3A4A5A6A7A8A9AAABACADAEAF
          01            # unsigned(1)
          81            # array(1)
             83         # array(3)
                26      # negative(6) / -7 = cose-alg-es256 /
                F6      # primitive(22) / null /
                F6      # primitive(22) / null /
          03            # unsigned(3) / versions: /
          81            # array(1) / [ 0 ] /
             00         # unsigned(0)
       03               # unsigned(3) / data-item-requested = attestation | trusted-components /

## Command
    echo -en "\x83\x01\xA3\x14\x50\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF\x01\x81\x83\x26\xF6\xF6\x03\x81\x00\x03" > query_request.cbor
