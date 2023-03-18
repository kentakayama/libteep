<!--
 Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.

 SPDX-License-Identifier: BSD-2-Clause
-->

# Update Message
    https://datatracker.ietf.org/doc/html/draft-ietf-teep-protocol-12#name-d4-update-message

## CBOR Diagnostic Notation
~~~~cbor-diag
/ update = /
[
  / type: / 3 / TEEP-TYPE-update /,
  / options: /
  {
    / token / 20 : h'A0A1A2A3A4A5A6A7A8A9AAABACADAEAF',
    / manifest-list / 10 : [
      <<
        / SUIT_Envelope / {
          / suit-authentication-wrapper / 2: << [
            << [
              / suit-digest-algorithm-id: / -16 / suit-cose-alg-sha256 /,
              / suit-digest-bytes: / h'DB601ADE73092B58532CA03FBB663DE49532435336F1558B49BB622726A2FEDD'
            ] >>,
            << / COSE_Sign1_Tagged / 18( [
              / protected: / << {
                / algorithm-id / 1: -7 / ES256 /
              } >>,
              / unprotected: / {},
              / payload: / null,
              / signature: / h'5B2D535A2B6D5E3C585C1074F414DA9E10BD285C99A33916DADE3ED38812504817AC48B62B8E984EC622785BD1C411888BE531B1B594507816B201F6F28579A4'
            ] ) >>
          ] >>,
          / suit-manifest / 3: << {
            / suit-manifest-version / 1: 1,
            / suit-manifest-sequence-number / 2: 3,
            / suit-common / 3: << {
              / suit-components / 2: [
                [
                  h'544545502D446576696365',           / "TEEP-Device" /
                  h'5365637572654653',                 / "SecureFS" /
                  h'8D82573A926D4754935332DC29997F74', / tc-uuid /
                  h'7461'                              / "ta" /
                ]
              ],
              / suit-common-sequence / 4: << [
                / suit-directive-override-parameters / 20, {
                  / suit-parameter-vendor-identifier / 1: h'C0DDD5F15243566087DB4F5B0AA26C2F',
                  / suit-parameter-class-identifier / 2: h'DB42F7093D8C55BAA8C5265FC5820F4E',
                  / suit-parameter-image-digest / 3: << [
                    / suit-digest-algorithm-id: / -16 / suit-cose-alg-sha256 /,
                    / suit-digest-bytes: / h'8CF71AC86AF31BE184EC7A05A411A8C3A14FD9B77A30D046397481469468ECE8'
                  ] >>,
                  / suit-parameter-image-size / 14: 20
                },
                / suit-condition-vendor-identifier / 1, 15,
                / suit-condition-class-identifier / 2, 15
              ] >>
            } >>,
            / suit-install / 9: << [
              / suit-directive-override-parameters / 20, {
                / suit-parameter-uri / 21: "https://example.org/8d82573a-926d-4754-9353-32dc29997f74.ta"
              },
              / suit-directive-fetch / 21, 15,
              / suit-condition-image-match / 3, 15
            ] >>
          } >>
        }
      >>
    ] / array of bstr wrapped SUIT_Envelope /
  }
]
~~~~


## CBOR Binary Representation
~~~~
82                  # array(2)
   03               # unsigned(3) / TEEP-TYPE-update /
   A2               # map(2)
      14            # unsigned(20) / token: /
      50            # bytes(16)
         A0A1A2A3A4A5A6A7A8A9AAABACADAEAF
      0A            # unsigned(10) / manifest-list: /
      81            # array(1)
         59 014E    # bytes(336)
            A2025873825824822F5820DB601ADE73092B58532CA03FBB663DE495
            32435336F1558B49BB622726A2FEDD584AD28443A10126A0F658405B2D53
            5A2B6D5E3C585C1074F414DA9E10BD285C99A33916DADE3ED38812504817
            AC48B62B8E984EC622785BD1C411888BE531B1B594507816B201F6F28579
            A40358D4A401010203035884A20281844B544545502D4465766963654853
            65637572654653508D82573A926D4754935332DC29997F74427461045854
            8614A40150C0DDD5F15243566087DB4F5B0AA26C2F0250DB42F7093D8C55
            BAA8C5265FC5820F4E035824822F58208CF71AC86AF31BE184EC7A05A411
            A8C3A14FD9B77A30D046397481469468ECE80E14010F020F0958458614A1
            15783B68747470733A2F2F6578616D706C652E6F72672F38643832353733
            612D393236642D343735342D393335332D3332646332393939376637342E
            7461150F030F
~~~~
