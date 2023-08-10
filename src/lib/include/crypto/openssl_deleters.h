/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/10.
//

#ifndef VIRTRU_OPENSSL_DELETERS_H
#define VIRTRU_OPENSSL_DELETERS_H

#include <cstdint>
#include <memory>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ec.h>
#include <openssl/param_build.h>

// All the required deleter's for the OpenSSL.
namespace virtru::crypto {

    // Deleter's
    struct BioDeleter { void operator()(BIO* bio) {::BIO_free(bio);} };
    using BIO_free_ptr = std::unique_ptr<BIO, BioDeleter>;

    struct BigNumDeleter { void operator()(BIGNUM* bigNum) {::BN_free(bigNum);} };
    using BIGNUM_free_ptr = std::unique_ptr<BIGNUM, BigNumDeleter>;

    struct EvpMdCtxDeleter { void operator()(EVP_MD_CTX* evp) {::EVP_MD_CTX_destroy(evp);} };
    using EVP_MD_CTX_free_ptr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

    struct X509Deleter { void operator()(X509* x509) {::X509_free(x509);} };
    using X509_free_ptr = std::unique_ptr<X509, X509Deleter>;
    
    struct EvpPkeyDeleter { void operator()(EVP_PKEY* pkey) {::EVP_PKEY_free(pkey);} };
    using EVP_PKEY_free_ptr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

    struct EvpPkeyCtxDeleter { void operator()(EVP_PKEY_CTX* pkeyCtx) {::EVP_PKEY_CTX_free(pkeyCtx);} };
    using EVP_PKEY_CTX_free_ptr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;

    struct EvpCipherCtxDelete { void operator()(EVP_CIPHER_CTX* evp) {::EVP_CIPHER_CTX_free(evp);} };
    using EVP_CIPHER_CTX_free_ptr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDelete>;

    struct ECPointDeleter { void operator()(EC_POINT* ecPoint) {::EC_POINT_free(ecPoint);} };
    using ECPoint_free_ptr = std::unique_ptr<EC_POINT, ECPointDeleter>;

    struct ECDSASigDeleter { void operator()(ECDSA_SIG* sig) {::ECDSA_SIG_free(sig);} };
    using ECDSASig_free_ptr = std::unique_ptr<ECDSA_SIG, ECDSASigDeleter>;

    struct OsslParamBldDeleter { void operator()(OSSL_PARAM_BLD* paramBld) {::OSSL_PARAM_BLD_free(paramBld);} };
    using OSSL_PARAM_BLD_free_ptr = std::unique_ptr<OSSL_PARAM_BLD, OsslParamBldDeleter>;

    struct OsslParamDeleter { void operator()(OSSL_PARAM* osslParam) {::OSSL_PARAM_free(osslParam);} };
    using OSSL_PARAM_free_ptr = std::unique_ptr<OSSL_PARAM, OsslParamDeleter>;

    struct EcGroupDeleter { void operator()(EC_GROUP* ecGroup) {::EC_GROUP_free(ecGroup);} };
    using EC_GROUP_free_ptr = std::unique_ptr<EC_GROUP, EcGroupDeleter>;

    struct OpensslBufDeleter { void operator()(std::uint8_t* ptr) {::OPENSSL_free(ptr);} };
    using Openssl_buf_free_ptr = std::unique_ptr<std::uint8_t, OpensslBufDeleter>;

}  // namespace virtru::crypto

#endif //VIRTRU_OPENSSL_DELETERS_H
