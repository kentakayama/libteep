<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# Success Message
    https://datatracker.ietf.org/doc/html/draft-ietf-teep-protocol-12#name-d5-success-message

## CBOR Diagnostic Notation
~~~~cbor-diag
/ teep-success = /
[
  / type: / 5 / TEEP-TYPE-teep-success /,
  / options: /
  {
    / token / 20 : h'A0A1A2A3A4A5A6A7A8A9AAABACADAEAF'
  }
]
~~~~


## CBOR Binary Representation
~~~~
82                  # array(2)
   05               # unsigned(5) / TEEP-TYPE-teep-success /
   A1               # map(1)
      14            # unsigned(20) / token: /
      50            # bytes(16)
         A0A1A2A3A4A5A6A7A8A9AAABACADAEAF
~~~~

## COSE_Sign protected Success Message in diag
~~~~
/ COSE_Sign1_Tagged = / 18([
  / protected: / << {
    / alg / 1 : -7 / ES256 /
  } >>,
  / unprotected: / {
    / kid / 4 : h'E96788B10B1610ABE478F9CE8DCFE2304C0911DD8CFEADDE25EC30CCB5A7B5AF' / TEEP Agent's key /
  },
  / payload: / << [
    / type: / 5 / TEEP-TYPE-Success /,
    / options: / {
      / token / 20 : h'A0A1A2A3A4A5A6A7A8A9AAABACADAEAF'
    }
  ] >>,
  / signature: / h'F12ED1E1699DDB77AC94266E1093FCF70BA8A11020FBAC1146F6B36AE3A1D484DCD5E4A008CC5DEA42F41DC022BAD549CC2320BDC6321ADFA2DA9C3709DA32E7'
])
~~~~

- [TEEP Agent's ES256 key](../examples/inc/teep_agent_es256_cose_key_public.h)
