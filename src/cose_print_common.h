#ifndef COSE_PRINT_COMMON_H
#define COSE_PRINT_COMMON_H

#include <stdint.h>
#include "teep/teep_common.h"

typedef char* (*TeepLabelToStr)(const int64_t, const int64_t);

char *teep_cose_mechanism_key_to_str(int64_t cose_mechanism_key);
char *teep_position_label_to_str(const int64_t label, const int64_t type);
char *teep_eat_claim_label_to_str(const int64_t label, const int64_t n);

teep_err_t teep_print_cose_usefulbufc(UsefulBufC cose,
                                      const uint32_t indent_space,
                                      const uint32_t indent_delta,
                                      TeepLabelToStr label_to_str);

#endif  /* COSE_PRINT_COMMON_H */
