/*
 * Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "teep/teep_cose.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "t_cose/t_cose_sign1_verify.h"
//#include "t_cose/t_cose_sign_sign.h"
//#include "t_cose/t_cose_sign_verify.h"
#include "t_cose/q_useful_buf.h"

teep_err_t teep_sign_cose_sign1(const UsefulBufC raw_cbor,
                                const teep_mechanism_t *mechanism,
                                UsefulBuf *returned_payload)
{
    // Create cose signed buffer.
    struct t_cose_sign1_sign_ctx sign_ctx;
    enum t_cose_err_t cose_result;
    UsefulBuf_MAKE_STACK_UB(auxiliary_buffer, TEEP_AUXILIARY_BUFFER_SIZE); // for EdDSA
    UsefulBufC tmp_signed_cose;

    t_cose_sign1_sign_init(&sign_ctx, 0, mechanism->key.cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, mechanism->key.cose_key, mechanism->key.kid);
    if (auxiliary_buffer.len > 0) {
        t_cose_sign1_sign_set_auxiliary_buffer(&sign_ctx, auxiliary_buffer);
    }

    cose_result = t_cose_sign1_sign(&sign_ctx, raw_cbor, *returned_payload, &tmp_signed_cose);
    if (cose_result != T_COSE_SUCCESS) {
        returned_payload->len = 0;
        return TEEP_ERR_SIGNING_FAILED;
    }
    *returned_payload = UsefulBuf_Unconst(tmp_signed_cose);
    return TEEP_SUCCESS;
}

teep_err_t teep_sign_cose_sign(const UsefulBufC raw_cbor,
                               const teep_mechanism_t mechanisms[],
                               const size_t num_mechanism,
                               UsefulBuf *returned_payload)
{
    // Create cose signed buffer.
    struct t_cose_sign_sign_ctx sign_ctx;
    enum t_cose_err_t cose_result;
    UsefulBuf_MAKE_STACK_UB(auxiliary_buffer, TEEP_AUXILIARY_BUFFER_SIZE); // for EdDSA
    UsefulBufC tmp_signed_cose;

    t_cose_sign_sign_init(&sign_ctx, T_COSE_OPT_MESSAGE_TYPE_SIGN);
    for (size_t i = 0; i < num_mechanism; i++) {
        teep_mechanism_t *mechanism = (teep_mechanism_t *)&mechanisms[i];

        switch (mechanism->key.cose_algorithm_id) {
        case T_COSE_ALGORITHM_EDDSA:
            t_cose_signature_sign_eddsa_init(&mechanism->key.signer_eddsa);
            t_cose_signature_sign_eddsa_set_signing_key(&mechanism->key.signer_eddsa, mechanism->key.cose_key, mechanism->key.kid);
            t_cose_signature_sign_eddsa_set_auxiliary_buffer(&mechanism->key.signer_eddsa, auxiliary_buffer);
            t_cose_sign_add_signer(&sign_ctx, t_cose_signature_sign_from_eddsa(&mechanism->key.signer_eddsa));
            break;
        case T_COSE_ALGORITHM_ES256:
        case T_COSE_ALGORITHM_ES384:
        case T_COSE_ALGORITHM_ES512:
            t_cose_signature_sign_main_init(&mechanism->key.signer_ecdsa, mechanism->key.cose_algorithm_id);
            t_cose_signature_sign_main_set_signing_key(&mechanism->key.signer_ecdsa, mechanism->key.cose_key, mechanisms[i].key.kid);

            t_cose_sign_add_signer(&sign_ctx, t_cose_signature_sign_from_main(&mechanism->key.signer_ecdsa));
            break;
        default:
            return TEEP_ERR_SIGNING_FAILED;
        }
    }

    cose_result = t_cose_sign_sign(&sign_ctx,
                                   NULLUsefulBufC,
                                   raw_cbor,
                                   *returned_payload,
                                   &tmp_signed_cose);
    if (cose_result != T_COSE_SUCCESS) {
        returned_payload->len = 0;
        return TEEP_ERR_SIGNING_FAILED;
    }
    *returned_payload = UsefulBuf_Unconst(tmp_signed_cose);

    return TEEP_SUCCESS;
}

teep_err_t teep_verify_cose_sign1(const UsefulBufC signed_cose,
                                  const teep_mechanism_t *mechanism,
                                  UsefulBufC *returned_payload)
{
    teep_err_t result = TEEP_SUCCESS;
    struct t_cose_sign1_verify_ctx verify_ctx;
    enum t_cose_err_t cose_result;
    UsefulBuf_MAKE_STACK_UB(auxiliary_buffer, TEEP_AUXILIARY_BUFFER_SIZE); // for EdDSA

    t_cose_sign1_verify_init(&verify_ctx, 0);
    t_cose_sign1_set_verification_key(&verify_ctx, mechanism->key.cose_key);
    if (auxiliary_buffer.len > 0) {
        t_cose_sign1_verify_set_auxiliary_buffer(&verify_ctx, auxiliary_buffer);
    }

    cose_result = t_cose_sign1_verify(&verify_ctx,
                                      signed_cose,
                                      returned_payload,
                                      NULL);
    if (cose_result != T_COSE_SUCCESS) {
        result = TEEP_ERR_VERIFICATION_FAILED;
    }
    return result;
}

teep_err_t teep_verify_cose_sign(const UsefulBufC signed_cose,
                                 const teep_mechanism_t mechanisms[],
                                 const size_t num_mechanism,
                                 UsefulBufC *returned_payload)
{
    teep_err_t result = TEEP_SUCCESS;
    struct t_cose_sign_verify_ctx verify_ctx;
    enum t_cose_err_t cose_result;
    UsefulBuf_MAKE_STACK_UB(auxiliary_buffer, TEEP_AUXILIARY_BUFFER_SIZE); // for EdDSA

    t_cose_sign_verify_init(&verify_ctx, T_COSE_OPT_MESSAGE_TYPE_SIGN);

    for (size_t i = 0; i < num_mechanism; i++) {
        teep_mechanism_t *mechanism = (teep_mechanism_t *)&mechanisms[i];
        if (mechanism->cose_tag != CBOR_TAG_COSE_SIGN) {
            return TEEP_ERR_INVALID_KEY;
        }

        if (mechanism->key.cose_algorithm_id == T_COSE_ALGORITHM_EDDSA) {
            t_cose_signature_verify_eddsa_init(&mechanism->key.verifier_eddsa, T_COSE_OPT_DECODE_ONLY);
            t_cose_signature_verify_eddsa_set_key(&mechanism->key.verifier_eddsa, mechanism->key.cose_key, mechanism->key.kid);
            t_cose_signature_verify_eddsa_set_auxiliary_buffer(&mechanism->key.verifier_eddsa, auxiliary_buffer);
            t_cose_sign_add_verifier(&verify_ctx, t_cose_signature_verify_from_eddsa(&mechanism->key.verifier_eddsa));

        }
        else {
            /* ECDSA */
            t_cose_signature_verify_main_init(&mechanism->key.verifier_ecdsa);
            t_cose_signature_verify_main_set_key(&mechanism->key.verifier_ecdsa, mechanism->key.cose_key, mechanisms[i].key.kid);

            t_cose_sign_add_verifier(&verify_ctx, t_cose_signature_verify_from_main(&mechanism->key.verifier_ecdsa));
        }
    }

    cose_result = t_cose_sign_verify(&verify_ctx,
                                     signed_cose,
                                     NULLUsefulBufC,
                                     returned_payload,
                                     NULL);
    if (cose_result != T_COSE_SUCCESS) {
        result = TEEP_ERR_VERIFICATION_FAILED;
    }
    return result;
}

#if defined(LIBTEEP_PSA_CRYPTO_C)
/*
    \brief      Internal function calls OpenSSL functions to create public key.

    \param[in]  key     Initialized teep_key_t, libteep abstraction structure.

    \return     This returns TEEP_SUCCESS or TEEP_ERR_FAILED_TO_VERIFY.
 */
teep_err_t teep_create_es_key(teep_key_t *key)
{
    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t     key_handle = 0;
    psa_status_t         result;

    psa_key_type_t type;
    psa_key_usage_t usage;
    psa_algorithm_t alg;
    switch (key->cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256:
        if (key->private_key == NULL) {
            type = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
            usage = PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT;
        }
        else {
            type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
            usage = PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_HASH;
        }
        alg = PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256);
        break;
    case T_COSE_ALGORITHM_ES384:
        if (key->private_key == NULL) {
            type = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
            usage = PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT;
        }
        else {
            type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
            usage = PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_HASH;
        }
        alg = PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_384);
        break;
    case T_COSE_ALGORITHM_ES512:
        if (key->private_key == NULL) {
            type = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
            usage = PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT;
        }
        else {
            type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
            usage = PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_HASH;
        }
        alg = PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_512);
        break;
    case T_COSE_ALGORITHM_EDDSA:
        if (key->private_key == NULL) {
            type = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS);
            usage = PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_EXPORT;
        }
        else {
            type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS);
            usage = PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_MESSAGE;
        }
        alg = PSA_ALG_PURE_EDDSA;
        break;
    default:
        return TEEP_ERR_INVALID_VALUE;
    }

    result = psa_crypto_init();
    if (result != PSA_SUCCESS) {
        return TEEP_ERR_VERIFICATION_FAILED;
    }

    psa_set_key_usage_flags(&key_attributes, usage);
    psa_set_key_algorithm(&key_attributes, alg);
    psa_set_key_type(&key_attributes, type);
    if (key->private_key == NULL) {
        result = psa_import_key(&key_attributes,
                                (const unsigned char*)key->public_key,
                                key->public_key_len,
                                &key_handle);
        if (result != PSA_SUCCESS) {
            return TEEP_ERR_VERIFICATION_FAILED;
        }
    }
    else {
        result = psa_import_key(&key_attributes,
                                (const unsigned char*)key->private_key,
                                key->private_key_len,
                                &key_handle);
        if (result != PSA_SUCCESS) {
            return TEEP_ERR_SIGNING_FAILED;
        }
    }

    key->cose_key.key.handle    = key_handle;

    return TEEP_SUCCESS;
}

#else /* LIBTEEP_PSA_CRYPTO_C */
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_300
/*
    \brief      Internal function calls OpenSSL functions to create public key.

    \param[in]  key     Initialized teep_key_t, libteep abstraction structure.

    \return     This returns TEEP_SUCCESS or TEEP_ERR_FAILED_TO_VERIFY.
 */
teep_err_t teep_create_es_key(teep_key_t *key)
{
    teep_err_t      result = TEEP_ERR_FATAL;
    EVP_PKEY        *pkey = NULL;
    EVP_PKEY_CTX    *ctx = NULL;
    OSSL_PARAM_BLD  *param_bld = NULL;
    OSSL_PARAM      *params = NULL;
    BIGNUM          *priv = NULL;

    int id;
    char *group_name;
    switch (key->cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256:
        id = EVP_PKEY_EC;
        group_name = SN_X9_62_prime256v1;
        break;
    case T_COSE_ALGORITHM_ES384:
        id = EVP_PKEY_EC;
        group_name = SN_secp384r1;
        break;
    case T_COSE_ALGORITHM_ES512:
        id = EVP_PKEY_EC;
        group_name = SN_secp521r1;
        break;
    case T_COSE_ALGORITHM_EDDSA:
        id = EVP_PKEY_ED25519;
        group_name = SN_ED25519;
        break;
    default:
        return TEEP_ERR_INVALID_VALUE;
    }

    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld == NULL) {
        return TEEP_ERR_FATAL;
    }
    if (!OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0)) {
        goto free_param_bld;
    }
    if (!OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, key->public_key, key->public_key_len)) {
        goto free_param_bld;
    }
    if (key->private_key != NULL) {
        /* XXX: Why do we need to convert private key to BN only for EcDSA? */
        switch (id) {
        case EVP_PKEY_EC:
            priv = BN_bin2bn(key->private_key, key->private_key_len, NULL);
            if (priv == NULL) {
                goto free_param_bld;
            }
            if (!OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, priv)) {
                goto free_param_bld;
            }
            break;

        case EVP_PKEY_ED25519:
            if (!OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, key->private_key, key->private_key_len)) {
                goto free_param_bld;
            }
            break;
        default:
            goto free_param_bld;
        }
    }
    params = OSSL_PARAM_BLD_to_param(param_bld);

    if (params == NULL) {
        goto free_param_bld;
    }
    ctx = EVP_PKEY_CTX_new_id(id, NULL);
    if (ctx == NULL) {
        goto free_params;
    }
    if (EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, &pkey, (key->private_key == NULL) ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR, params) <= 0) {
        goto free_ctx;
    }

    key->cose_key.key.ptr = pkey;
    result = TEEP_SUCCESS;

free_ctx:
    EVP_PKEY_CTX_free(ctx);
free_params:
    OSSL_PARAM_free(params);
    if (priv != NULL) {
        BN_free(priv);
    }
free_param_bld:
    OSSL_PARAM_BLD_free(param_bld);
    return result;
}
#else /* OPENSSL_VERSION_NUMBER < OPENSSL_VERSION_300 */
/*
    \brief      Internal function calls OpenSSL functions to create public key.

    \param[in]  key     Initialized teep_key_t, libteep abstraction structure.

    \return     This returns TEEP_SUCCESS or TEEP_ERR_FAILED_TO_VERIFY.
 */
teep_err_t teep_create_es_key(teep_key_t *key)
{
    /* ****************************************** */
    /* cose algorithm enum -> openssl group name  */
    /* ****************************************** */
    const char *group_name;
    switch (key->cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256:
        group_name = "prime256v1";
        break;
    case T_COSE_ALGORITHM_ES384:
        group_name = "secp384r1";
        break;
    case T_COSE_ALGORITHM_ES512:
        group_name = "secp521r1";
        break;
    default:
        return TEEP_ERR_INVALID_VALUE;
    }

    /* ********************************* */
    /* create EC_KEY based on group name */
    /* ********************************* */
    int curveID = OBJ_txt2nid(group_name);
    EC_KEY *pEC = EC_KEY_new_by_curve_name(curveID);
    if (!pEC) {
        return TEEP_ERR_FATAL;
    }

    /* ****************************************************************** */
    /* set a public key raw data and a private key raw data into EC_KEY   */
    /* ****************************************************************** */
    if(!EC_KEY_oct2key(pEC,(unsigned char*) key->public_key, key->public_key_len, NULL)) {
        goto err;
    }
    if (key->private_key != NULL) {
        if(!EC_KEY_oct2priv(pEC,(unsigned char*) key->private_key, key->private_key_len)) {
            goto err;
        }
    }

    /* ************************* */
    /* validity check of EC_KEY  */
    /* ************************* */
    if (!EC_KEY_check_key(pEC)){
        goto err;
    }

    /* *************************************** */
    /* EC_KEY -> EVP_PKEY and set out variable */
    /* *************************************** */
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!EVP_PKEY_set1_EC_KEY(pkey, pEC)) {
        goto err;
    } else {
        key->cose_key.key.ptr   = pkey;
        EC_KEY_free(pEC);
        return TEEP_SUCCESS;
    }
err:
    EC_KEY_free(pEC);
    return TEEP_ERR_FATAL;
}
#endif /* OPENSSL_VERSION_NUMBER */
#endif /* LIBTEEP_PSA_CRYPTO_C */

teep_err_t teep_key_init_es256_key_pair(const unsigned char *private_key,
                                        const unsigned char *public_key,
                                        UsefulBufC kid,
                                        teep_key_t *cose_key_pair)
{
    cose_key_pair->private_key = private_key;
    cose_key_pair->private_key_len = (private_key == NULL) ? 0 : PRIME256V1_PRIVATE_KEY_LENGTH;
    cose_key_pair->public_key = public_key;
    cose_key_pair->public_key_len = PRIME256V1_PUBLIC_KEY_LENGTH;
    cose_key_pair->cose_algorithm_id = T_COSE_ALGORITHM_ES256;
    cose_key_pair->kid = kid;
    return teep_create_es_key(cose_key_pair);
}

teep_err_t teep_key_init_es384_key_pair(const unsigned char *private_key,
                                        const unsigned char *public_key,
                                        UsefulBufC kid,
                                        teep_key_t *cose_key_pair)
{
    cose_key_pair->private_key = private_key;
    cose_key_pair->private_key_len = (private_key == NULL) ? 0 : SECP384R1_PRIVATE_KEY_LENGTH;
    cose_key_pair->public_key = public_key;
    cose_key_pair->public_key_len = SECP384R1_PUBLIC_KEY_LENGTH;
    cose_key_pair->cose_algorithm_id = T_COSE_ALGORITHM_ES384;
    cose_key_pair->kid = kid;
    return teep_create_es_key(cose_key_pair);
}

teep_err_t teep_key_init_es521_key_pair(const unsigned char *private_key,
                                        const unsigned char *public_key,
                                        UsefulBufC kid,
                                        teep_key_t *cose_key_pair)
{
    cose_key_pair->private_key = private_key;
    cose_key_pair->private_key_len = (private_key == NULL) ? 0 : SECP521R1_PRIVATE_KEY_LENGTH;
    cose_key_pair->public_key = public_key;
    cose_key_pair->public_key_len = SECP521R1_PUBLIC_KEY_LENGTH;
    cose_key_pair->cose_algorithm_id = T_COSE_ALGORITHM_ES512;
    cose_key_pair->kid = kid;
    return teep_create_es_key(cose_key_pair);
}

teep_err_t teep_key_init_ed25519_key_pair(const unsigned char *private_key,
                                          const unsigned char *public_key,
                                          UsefulBufC kid,
                                          teep_key_t *cose_key_pair)
{
    cose_key_pair->private_key = private_key;
    cose_key_pair->private_key_len = (private_key == NULL) ? 0 : ED25519_PRIVATE_KEY_LENGTH;
    cose_key_pair->public_key = public_key;
    cose_key_pair->public_key_len = ED25519_PUBLIC_KEY_LENGTH;
    cose_key_pair->cose_algorithm_id = T_COSE_ALGORITHM_EDDSA;
    cose_key_pair->kid = kid;
    return teep_create_es_key(cose_key_pair);
}

teep_err_t teep_key_init_es256_public_key(const unsigned char *public_key,
                                          UsefulBufC kid,
                                          teep_key_t *cose_public_key)
{
    return teep_key_init_es256_key_pair(NULL, public_key, kid, cose_public_key);
}

teep_err_t teep_key_init_es384_public_key(const unsigned char *public_key,
                                          UsefulBufC kid,
                                          teep_key_t *cose_public_key)
{
    return teep_key_init_es384_key_pair(NULL, public_key, kid, cose_public_key);
}

teep_err_t teep_key_init_es521_public_key(const unsigned char *public_key,
                                          UsefulBufC kid,
                                          teep_key_t *cose_public_key)
{
    return teep_key_init_es521_key_pair(NULL, public_key, kid, cose_public_key);
}

teep_err_t teep_key_init_ed25519_public_key(const unsigned char *public_key,
                                            UsefulBufC kid,
                                            teep_key_t *cose_public_key)
{
    return teep_key_init_ed25519_key_pair(NULL, public_key, kid, cose_public_key);
}

teep_err_t teep_free_key(const teep_key_t *key) {
#if defined(LIBTEEP_PSA_CRYPTO_C)
    psa_destroy_key((psa_key_handle_t)key->cose_key.key.handle);
#else
    EVP_PKEY_free(key->cose_key.key.ptr);
#endif
    return TEEP_SUCCESS;
}

teep_err_t teep_set_mechanism_from_cose_key_from_item(QCBORDecodeContext *context,
                                                      QCBORItem *item,
                                                      UsefulBufC kid,
                                                      teep_mechanism_t *mechanism)
{
    teep_err_t result;
    QCBORError error;
    if (item->uDataType != QCBOR_TYPE_MAP) {
        return TEEP_ERR_INVALID_TYPE_OF_VALUE;
    }
    UsefulBuf_MAKE_STACK_UB(public_key, TEEP_MAX_PUBLIC_KEY_LEN); // for ECDSA (x, y) parameters
    int64_t crv = 0;
    int64_t kty = 0;

    UsefulBufC y = NULLUsefulBufC;
    UsefulBufC x = NULLUsefulBufC;
    UsefulBufC d = NULLUsefulBufC;
    QCBORDecode_EnterMap(context, item);
    const size_t cose_key_map_len = item->val.uCount;
    for (size_t k = 0; k < cose_key_map_len; k++) {
        QCBORDecode_GetNext(context, item);
        if (item->uLabelType != QCBOR_TYPE_INT64) {
            return TEEP_ERR_INVALID_TYPE_OF_KEY;
        }
        switch (item->label.int64) {
        case TEEP_COSE_D:
            if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
                return TEEP_ERR_INVALID_TYPE_OF_VALUE;
            }
            d = item->val.string;
            break;
        case TEEP_COSE_Y:
            if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
                return TEEP_ERR_INVALID_TYPE_OF_VALUE;
            }
            y = item->val.string;
            break;
        case TEEP_COSE_X:
            if (item->uDataType != QCBOR_TYPE_BYTE_STRING) {
                return TEEP_ERR_INVALID_TYPE_OF_VALUE;
            }
            x = item->val.string;
            break;
        case TEEP_COSE_CRV:
            if (item->uDataType != QCBOR_TYPE_INT64) {
                return TEEP_ERR_INVALID_TYPE_OF_VALUE;
            }
            crv = item->val.int64;
            break;
        case TEEP_COSE_KTY:
            if (item->uDataType != QCBOR_TYPE_INT64) {
                return TEEP_ERR_INVALID_TYPE_OF_VALUE;
            }
            kty = item->val.int64;
            break;
        default:
            return TEEP_ERR_NOT_IMPLEMENTED;
        }
    }
    QCBORDecode_ExitMap(context);
    error = QCBORDecode_GetError(context);
    if (error != QCBOR_SUCCESS) {
        return TEEP_ERR_FATAL;
    }

    /* check kty */
    switch (kty) {
    case TEEP_COSE_KTY_EC2:
        switch (crv) {
        case TEEP_COSE_CRV_P256:
            if ((x.len == 32) &&
                (y.len == 32)) {
                /* POINT_CONVERSION_UNCOMPRESSED */
                ((uint8_t *)public_key.ptr)[0] = 0x04;
                memcpy(&((uint8_t *)public_key.ptr)[1], x.ptr, 32);
                memcpy(&((uint8_t *)public_key.ptr)[33], y.ptr, 32);
                public_key.len = PRIME256V1_PUBLIC_KEY_LENGTH;
            }
            else {
                return TEEP_ERR_INVALID_VALUE;
            }
            if (d.len == PRIME256V1_PRIVATE_KEY_LENGTH) {
                result = teep_key_init_es256_key_pair(d.ptr, public_key.ptr, kid, &mechanism->key);
            }
            else if (d.len == 0) {
                result = teep_key_init_es256_public_key(public_key.ptr, kid, &mechanism->key);
            }
            else {
                return TEEP_ERR_INVALID_VALUE;
            }
            if (result != TEEP_SUCCESS) {
                return result;
            }
            break; /* COSE_KEY_CRV_P256 */

        default:
            return TEEP_ERR_NOT_IMPLEMENTED;
        }
        break; /* TEEP_COSE_KTY_EC2 */

    case TEEP_COSE_KTY_OKP:
        switch (crv) {
        case TEEP_COSE_CRV_ED25519:
            if (x.len != ED25519_PUBLIC_KEY_LENGTH) {
                return TEEP_ERR_INVALID_VALUE;
            }
            if (d.len == ED25519_PRIVATE_KEY_LENGTH) {
                result = teep_key_init_ed25519_key_pair(d.ptr, x.ptr, kid, &mechanism->key);
            }
            else if (d.len == 0) {
                result = teep_key_init_ed25519_public_key(public_key.ptr, kid, &mechanism->key);
            }
            else {
                return TEEP_ERR_INVALID_VALUE;
            }
            if (result != TEEP_SUCCESS) {
                return result;
            }
            break; /* COSE_KEY_CRV_P256 */

        default:
            return TEEP_ERR_NOT_IMPLEMENTED;
        }
        break; /* TEEP_COSE_KTY_EC2 */


    default:
        return TEEP_ERR_INVALID_TYPE_OF_VALUE;
    }
    error = QCBORDecode_GetError(context);
    if (error != QCBOR_SUCCESS) {
        return TEEP_ERR_FATAL;
    }
    return TEEP_SUCCESS;
}

teep_err_t teep_set_mechanism_from_cose_key(UsefulBufC buf,
                                            UsefulBufC kid,
                                            teep_mechanism_t *mechanism)
{
    QCBORDecodeContext decode_context;
    QCBORItem item;
    QCBORDecode_Init(&decode_context, buf, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_PeekNext(&decode_context, &item);
    teep_err_t result = teep_set_mechanism_from_cose_key_from_item(&decode_context, &item, kid, mechanism);
    if (result != TEEP_SUCCESS) {
        return result;
    }
    QCBORError error = QCBORDecode_Finish(&decode_context);
    if (error != QCBOR_SUCCESS) {
        return TEEP_ERR_FATAL;
    }
    return TEEP_SUCCESS;
}

#if defined(LIBTEEP_PSA_CRYPTO_C)
teep_err_t teep_generate_sha256(UsefulBufC target,
                                UsefulBuf hash)
{
    if(hash.len != SHA256_DIGEST_LENGTH)
        return( TEEP_ERR_NO_MEMORY );

    psa_status_t status;
    size_t real_hash_size;
    psa_hash_operation_t sha256_psa = PSA_HASH_OPERATION_INIT;

    status = psa_crypto_init( );
    if( status != PSA_SUCCESS )
        return( TEEP_ERR_FATAL );

    status = psa_hash_setup( &sha256_psa, PSA_ALG_SHA_256 );
    if( status != PSA_SUCCESS )
        return( TEEP_ERR_FATAL );

    status = psa_hash_update( &sha256_psa, target.ptr, target.len );
    if( status != PSA_SUCCESS )
        return( TEEP_ERR_FATAL );

    status = psa_hash_finish( &sha256_psa, hash.ptr, hash.len, &real_hash_size );
    if( status != PSA_SUCCESS )
        return( TEEP_ERR_FATAL );

    if(real_hash_size != SHA256_DIGEST_LENGTH)
        return( TEEP_ERR_NO_MEMORY );

    return TEEP_SUCCESS;
}
#else
teep_err_t teep_generate_sha256(UsefulBufC target,
                                UsefulBuf hash)
{
    if (hash.len != SHA256_DIGEST_LENGTH) {
        return TEEP_ERR_NO_MEMORY;
    }

    teep_err_t result = TEEP_ERR_FATAL;
    unsigned int generated_size;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx != NULL
        && EVP_DigestInit(ctx, EVP_sha256())
        && EVP_DigestUpdate(ctx, target.ptr, target.len)
        && EVP_DigestFinal(ctx, hash.ptr, &generated_size)
        && hash.len == generated_size) {
        result = TEEP_SUCCESS;
    }
    if (ctx != NULL) {
        EVP_MD_CTX_free(ctx);
    }
    return result;
}
#endif /* LIBTEEP_PSA_CRYPTO_C */

/* maximum temporary buffer is for ES512 + P-521
 * 0xA4
 *    0x01      # 1     = kty
 *    0x02      # 2     = EC2
 *    0x20      # -1    = crv
 *    0x03      # 3     = P521
 *    0x21      # -2    = x
 *    0x58 42   # bytes(66)
 *       XXXX...
 *    0x22      # -3    = y
 *    0x58 42   # bytes(66)
 *       XXXX...
 *
 * NOTE: Currently this does NOT support HSS-LMS
 */
#define COSE_KEY_THUMBPRINT_BUFFER_SIZE (11+66+66)
teep_err_t teep_calc_cose_key_thumbprint(UsefulBufC cose_key,
                                         UsefulBuf thumbprint)
{
    if (thumbprint.len != 32) {
        /* not SHA-256 size */
        return TEEP_ERR_NO_MEMORY;
    }

    int64_t kty = 0;
    int64_t crv = 0;
    UsefulBufC x = NULLUsefulBufC; // for OKP and EC2
    UsefulBufC y = NULLUsefulBufC; // for EC2
    UsefulBufC k = NULLUsefulBufC; // for Symmetric
    bool try = true;
    QCBORError error;
    QCBORDecodeContext decode_context;
    QCBORItem item;
    UsefulBuf_MAKE_STACK_UB(buf, COSE_KEY_THUMBPRINT_BUFFER_SIZE);

retry:
    /* extract necessary values in COSE_Key struct */
    QCBORDecode_Init(&decode_context, cose_key, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterMap(&decode_context, &item);
    const size_t cose_key_map_len = item.val.uCount;
    for (size_t i = 0; i < cose_key_map_len; i++) {
        QCBORDecode_GetNext(&decode_context, &item);
        if (item.uLabelType != QCBOR_TYPE_INT64) {
            return TEEP_ERR_INVALID_TYPE_OF_KEY;
        }
        switch (item.label.int64) {
        case TEEP_COSE_KTY:
            if (item.uDataType != QCBOR_TYPE_INT64) {
                return TEEP_ERR_INVALID_TYPE_OF_VALUE;
            }
            kty = item.val.int64;
            break;

        case -1:
            /* crv for OKP and EC2, k for Symmetric */
            switch (kty) {
            case TEEP_COSE_KTY_OKP:
            case TEEP_COSE_KTY_EC2:
                if (item.uDataType != QCBOR_TYPE_INT64) {
                    return TEEP_ERR_INVALID_TYPE_OF_VALUE;
                }
                crv = item.val.int64;
                break;
            case TEEP_COSE_KTY_SYMMETRIC:
                if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                    return TEEP_ERR_INVALID_TYPE_OF_VALUE;
                }
                k = item.val.string;
                break;
            default:
                if (try) {
                    try = false;
                    goto retry;
                }
                else {
                    return TEEP_ERR_INVALID_VALUE;
                }
            }
            break;

        case -2:
            /* x for OKP and EC2 */
            switch (kty) {
            case TEEP_COSE_KTY_OKP:
            case TEEP_COSE_KTY_EC2:
                if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                    return TEEP_ERR_INVALID_TYPE_OF_VALUE;
                }
                x = item.val.string;
                break;
            default:
                if (try) {
                    try = false;
                    goto retry;
                }
                else {
                    return TEEP_ERR_INVALID_VALUE;
                }
            }
            break;

        case -3:
            /* y for EC2 */
            switch (kty) {
            case TEEP_COSE_KTY_EC2:
                if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                    return TEEP_ERR_INVALID_TYPE_OF_VALUE;
                }
                y = item.val.string;
                break;
            default:
                if (try) {
                    try = false;
                    goto retry;
                }
                else {
                    return TEEP_ERR_INVALID_VALUE;
                }
            }
            break;

        default:
            /* ignore */
            break;
        }
    }
    QCBORDecode_ExitMap(&decode_context);

    error = QCBORDecode_Finish(&decode_context);
    if (error != QCBOR_SUCCESS) {
        return TEEP_ERR_DECODING_FAILED;
    }

    /* calculate thumbprint */
    UsefulBufC tmp;
    QCBOREncodeContext encode_context;
    QCBOREncode_Init(&encode_context, buf);

    switch (kty) {
    case TEEP_COSE_KTY_OKP:
        /* check curve and public key size */
        switch (crv) {
        case TEEP_COSE_CRV_X25519:
            if (x.len != 32) {
                return TEEP_ERR_INVALID_VALUE;
            }
            break;
        case TEEP_COSE_CRV_X448:
            if (x.len != 57) {
                return TEEP_ERR_INVALID_VALUE;
            }
            break;
        case TEEP_COSE_CRV_ED25519:
            if (x.len != 32) {
                return TEEP_ERR_INVALID_VALUE;
            }
            break;
        case TEEP_COSE_CRV_ED448:
            if (x.len != 57) {
                return TEEP_ERR_INVALID_VALUE;
            }
            break;
        default:
            return TEEP_ERR_INVALID_VALUE;
        }

        /* deterministicly encode it */
        QCBOREncode_OpenMap(&encode_context);
        QCBOREncode_AddInt64ToMapN(&encode_context, TEEP_COSE_KTY, TEEP_COSE_KTY_OKP);
        QCBOREncode_AddInt64ToMapN(&encode_context, TEEP_COSE_CRV, crv);
        QCBOREncode_AddBytesToMapN(&encode_context, TEEP_COSE_X, x);
        QCBOREncode_CloseMap(&encode_context);
        break;

    case TEEP_COSE_KTY_EC2:
        /* check curve and public key size */
        switch (crv) {
        case TEEP_COSE_CRV_P256:
            if (x.len != 32 || y.len != 32) {
                return TEEP_ERR_INVALID_VALUE;
            }
            break;
        case TEEP_COSE_CRV_P384:
            if (x.len != 48 || y.len != 48) {
                return TEEP_ERR_INVALID_VALUE;
            }
            break;
        case TEEP_COSE_CRV_P521:
            if (x.len != 66 || y.len != 66) {
                return TEEP_ERR_INVALID_VALUE;
            }
            break;
        default:
            return TEEP_ERR_INVALID_VALUE;
        }

        /* deterministicly encode it */
        QCBOREncode_OpenMap(&encode_context);
        QCBOREncode_AddInt64ToMapN(&encode_context, TEEP_COSE_KTY, TEEP_COSE_KTY_EC2);
        QCBOREncode_AddInt64ToMapN(&encode_context, TEEP_COSE_CRV, crv);
        QCBOREncode_AddBytesToMapN(&encode_context, TEEP_COSE_X, x);
        QCBOREncode_AddBytesToMapN(&encode_context, TEEP_COSE_Y, y);
        QCBOREncode_CloseMap(&encode_context);
        break;

    case TEEP_COSE_KTY_SYMMETRIC:
        if (k.len == 0) {
            return TEEP_ERR_INVALID_VALUE;
        }

        /* deterministicly encode it */
        QCBOREncode_OpenMap(&encode_context);
        QCBOREncode_AddInt64ToMapN(&encode_context, TEEP_COSE_KTY, TEEP_COSE_KTY_SYMMETRIC);
        QCBOREncode_AddBytesToMapN(&encode_context, TEEP_COSE_K, k);
        QCBOREncode_CloseMap(&encode_context);
        break;

    default:
        return TEEP_ERR_INVALID_VALUE;
    }

    error = QCBOREncode_Finish(&encode_context, &tmp);
    if (error != QCBOR_SUCCESS) {
        return TEEP_ERR_ENCODING_FAILED;
    }

    /* now generate the thumbprint using SHA-256 */
    return teep_generate_sha256(tmp, thumbprint);
}
