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

.PHONY: all clean

all: $(TARGETS)

CODE_PAT	:= ^\~\~\~\~

%.cbor: %.md
	sed -n '/${CODE_PAT}cbor-diag/,/${CODE_PAT}/ p' < $^ | sed '/${CODE_PAT}.*/ d' | diag2cbor.rb > $@

clean:
	$(RM) -f $(TARGETS)
