#
# Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

TARGETS	:=	query_request.cbor \
			query_response.cbor \
			update.cbor \
			teep_success.cbor \
			teep_error.cbor \
			evidence.cbor \
			attestation_results.cbor

.PHONY: all
all: $(TARGETS)

CODE_PAT	:= ^\~\~\~\~

%.cbor: %.md
	sed -n '/${CODE_PAT}cbor-diag/,/${CODE_PAT}/ p' < $^ | sed '/${CODE_PAT}.*/ d' | diag2cbor.rb > $@

# TAM Sign (Multiple)
query_request_cose.cbor: query_request.cbor ../bin/teep_cose_tam0
	../bin/teep_cose_tam0 $< $@

# TAM Sign1
update_cose.cbor: update.cbor ../bin/teep_cose_tam1
	../bin/teep_cose_tam1 $< $@

# Agent Sign1
query_response_cose.cbor: query_response.cbor ../bin/teep_cose_agent
teep_success_cose.cbor: teep_success.cbor ../bin/teep_cose_agent
teep_error_cose.cbor: teep_error.cbor ../bin/teep_cose_agent
evidence_cose.cbor: evidence.cbor ../bin/teep_cose_agent
	../bin/teep_cose_agent $< $@

# Verifier Sign1
attestation_results_cose.cbor: attestation_results.cbor ../bin/teep_cose_verifier
	../bin/teep_cose_verifier $< $@

.PHONY: sign
sign: $(TARGETS:%.cbor=%_cose.cbor)

.PHONY: clean
clean:
	$(RM) -f $(TARGETS)
