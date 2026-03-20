# Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
# SPDX-License-Identifier: BSD-2-Clause

# Stable example image for consumers of libteep.
# All upstream sources are pinned by default for reproducible rebuilds.

FROM debian:12-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive
ARG QCBOR_REF=590a23daf65af068cee81555c597063150e23539
ARG T_COSE_REF=d5b1bd23b69d777672ae0152f8ebcdaa5aef0384
ARG LIBTEEP_REF=f247d3f71b704f0c428ade066ce6fb82a1210e04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      gcc \
      libc6-dev \
      make \
      libcurl4-openssl-dev \
      libssl-dev && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/laurencelundblade/QCBOR.git /tmp/QCBOR && \
    cd /tmp/QCBOR && \
    git fetch --depth 1 origin "${QCBOR_REF}" && \
    git checkout --detach "${QCBOR_REF}" && \
    make libqcbor.a install

RUN git clone --depth 1 https://github.com/kentakayama/t_cose.git /tmp/t_cose && \
    cd /tmp/t_cose && \
    git fetch --depth 1 origin "${T_COSE_REF}" && \
    git checkout --detach "${T_COSE_REF}" && \
    make -f Makefile.ossl libt_cose.a install

RUN git clone --depth 1 https://github.com/kentakayama/libteep.git /tmp/libteep && \
    cd /tmp/libteep && \
    git fetch --depth 1 origin "${LIBTEEP_REF}" && \
    git checkout --detach "${LIBTEEP_REF}" && \
    make -f examples/teep_over_http_client/Makefile

FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      libcurl4 \
      libssl3 && \
    rm -rf /var/lib/apt/lists/* && \
    addgroup --system libteep && \
    adduser --system --ingroup libteep libteep

COPY --from=builder /usr/local /usr/local
COPY --from=builder /tmp/libteep/bin/teep_http_client /usr/local/bin/teep_http_client

USER libteep
CMD ["/bin/sh", "-lc", "exec /usr/local/bin/teep_http_client \"${TAM_URI}\""]
