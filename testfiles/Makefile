#
# Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

TARGETS	:= query_request.cbor
TARGETS += query_response.cbor
TARGETS += update.cbor
TARGETS += teep_success.cbor
TARGETS += teep_error.cbor

SIGNED_TARGETS := query_request.tam.cose
SIGNED_TARGETS += query_response.agent.cose
SIGNED_TARGETS += update.tam.cose
SIGNED_TARGETS += teep_success.agent.cose
SIGNED_TARGETS += teep_error.agent.cose

.PHONY: all
all: $(TARGETS)

CODE_PAT := ^\~\~\~\~

%.cbor: %.md
	sed -n '/${CODE_PAT}cbor-diag/,/${CODE_PAT}/ p' < $^ | sed '/${CODE_PAT}.*/ d' | diag2cbor.rb > $@

# TAM Sign1
%.tam.cose: %.cbor
	../bin/teep_cose_tam $< $@

# Agent Sign1
%.agent.cose: %.cbor
	../bin/teep_cose_agent $< $@

.PHONY: sign
sign: $(SIGNED_TARGETS)

.PHONY: clean
clean:
	$(RM) -f $(TARGETS)
	$(RM) -f $(SIGNED_TARGETS)
