<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# Success Message
    https://datatracker.ietf.org/doc/html/draft-ietf-teep-protocol-26#name-d5-success-message

## CBOR Diagnostic Notation
~~~~cbor-diag
/ teep-success = /
[
  / type: / 4 / TEEP-TYPE-success /,
  / options: /
  {
    / token / 19 : h'A0A1A2A3A4A5A6A7A8A9AAABACADAEAF'
  }
]
~~~~


## CBOR Binary Representation
~~~~
82                  # array(2)
   04               # unsigned(4) / TEEP-TYPE-success /
   A1               # map(1)
      13            # unsigned(19) / token: /
      50            # bytes(16)
         A0A1A2A3A4A5A6A7A8A9AAABACADAEAF
~~~~
