/*
* Copyright 2020 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/04/20.
//

/*
 * Migration guide to openssl - https://www.openssl.org/docs/man3.0/man7/migration_guide.html
 */

#include "ec_key_pair.h"
#include "crypto_utils.h"
#include "tdf_exception.h"

#include <boost/algorithm/string.hpp>
#include <type_traits>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

namespace virtru::crypto {

    /// Constants
    constexpr auto kX509CertTag = "BEGIN CERTIFICATE";
    constexpr auto SECP256R1_CURVE = "secp256r1";
    constexpr auto PRIME256V1_CURVE = "prime256v1";
    constexpr auto SECP384R1_CURVE = "secp384r1";
    constexpr auto SECP521R1_CURVE = "secp521r1";
    constexpr auto SHA2_256 = "SHA2-256";

    /// Constructor
    ECKeyPair::ECKeyPair(EVP_PKEY_free_ptr pkey)
        : m_pkey(std::move(pkey)) {}

    /// Creates an instance of EC(Elliptic Curve) Key and will generate a new key pair every time it is called.
    std::unique_ptr<ECKeyPair> ECKeyPair::Generate(const std::string& curveName) {

        EVP_PKEY_free_ptr evppkeyPtr { EVP_EC_gen(curveName.data())};
        if (!evppkeyPtr) {
            ThrowOpensslException("Error assigning EC key to EVP_PKEY structure.");
        }

        return std::unique_ptr<ECKeyPair>(new ECKeyPair(std::move(evppkeyPtr)));
    }

    /// Return public key in PEM format.
    std::string ECKeyPair::PublicKeyInPEMFormat() const {
        BIO_free_ptr bio{BIO_new(BIO_s_mem())};

        if (1 != PEM_write_bio_PUBKEY(bio.get(), m_pkey.get())) {
            ThrowOpensslException("Error writing EC public key data in PEM format.");
        }

        // Read the public key from the buffer and put it in the string
        std::string publicKeyPem(BIO_pending(bio.get()), '\0');
        auto readResult = BIO_read(bio.get(), publicKeyPem.data(), static_cast<int>(publicKeyPem.size()));
        if (readResult <= 0) {
            ThrowOpensslException("Failed to read public key data.");
        }

        return publicKeyPem;
    }

    /// Return private key in PEM format.
    std::string ECKeyPair::PrivateKeyInPEMFormat() const {
        BIO_free_ptr bio{BIO_new(BIO_s_mem())};

        if (!PEM_write_bio_PrivateKey(bio.get(), m_pkey.get(), nullptr,
                nullptr, 0, 0, nullptr)) {
            ThrowOpensslException("Error writing EC private key data in PEM format.");
        }

        // Read the private key from the buffer and put it in the string
        std::string privateKeyPem(BIO_pending(bio.get()), '\0');
        auto readResult = BIO_read(bio.get(), privateKeyPem.data(), static_cast<int>(privateKeyPem.size()));
        if (readResult <= 0) {
            ThrowOpensslException("Failed to read private key data.");
        }

        return privateKeyPem;
    }

    /// Return the key size in bits.
    unsigned int ECKeyPair::KeySize() const {
        return EVP_PKEY_bits(m_pkey.get());
    }

    /// Return the curve name.
    std::string ECKeyPair::CurveName() const {
        // Info-https://www.openssl.org/docs/manmaster/man7/EVP_PKEY-EC.html
        size_t len{};
        auto result =  EVP_PKEY_get_utf8_string_param(m_pkey.get(),
                                                      OSSL_PKEY_PARAM_GROUP_NAME,
                                                       nullptr,
                                                       0,
                                                       &len);
        if(!result){
            ThrowOpensslException("Failed to get the length of curve name from ec key.");
        }


        std::string curveName(len+1, '0');
        result =  EVP_PKEY_get_utf8_string_param(m_pkey.get(),
                                                 OSSL_PKEY_PARAM_GROUP_NAME,
                                                 curveName.data(),
                                                 curveName.size(),
                                                 &len);
        if(!result){
            ThrowOpensslException("Failed to get the curve name from ec key.");
        };

        curveName.resize(len);
        std::string curve(curveName);
        return curve;
    }

    /// Generate a public key given the private key and it's curve.
    std::string ECKeyPair::GetPEMPublicKeyFromPrivateKey(const std::string& privateKeyInPEM,
                                                     const std::string& curveName) {

        auto curveNid = OBJ_txt2nid(curveName.data());
        if (curveNid == NID_undef) {
            ThrowOpensslException("Unknown curve name.");
        }

        /// Extract private key as big number from the pem formatted private key
        BIO_free_ptr preBio{BIO_new(BIO_s_mem())};
        if ((size_t)BIO_write(preBio.get(), privateKeyInPEM.data(), privateKeyInPEM.size()) != privateKeyInPEM.size()) {
            ThrowOpensslException("Failed to load private key.");
        }

        EVP_PKEY_free_ptr ecPre {PEM_read_bio_PrivateKey(preBio.get(), nullptr, nullptr, nullptr)};
        if (!ecPre) {
            ThrowOpensslException("Failed to read ec private key from pem format");
        }

        EVP_PKEY_CTX_free_ptr evpPkeyCtxPtr { EVP_PKEY_CTX_new(ecPre.get(), nullptr)};
        if (!evpPkeyCtxPtr) {
            ThrowOpensslException("Failed to create EVP_PKEY_CTX.");
        }

        if (1 != EVP_PKEY_private_check(evpPkeyCtxPtr.get())) {
            ThrowOpensslException("Failed ec key(private) sanity check.");
        }

        BIGNUM* bnPriv = nullptr;
        auto result = EVP_PKEY_get_bn_param(ecPre.get(), OSSL_PKEY_PARAM_PRIV_KEY, &bnPriv);
        if (!result) {
            ThrowOpensslException("Failed to read ec bn using EVP_PKEY_get_bn_param.");
        }
        BIGNUM_free_ptr bnPrivPtr{bnPriv};

        EC_GROUP_free_ptr ecGroupFreePtr{EC_GROUP_new_by_curve_name(curveNid)};
        if (!ecGroupFreePtr) {
            ThrowOpensslException("Failed to create a group from EC curve.");
        }

        // Create a ECPoint and generate a public key.
        ECPoint_free_ptr pubKey{EC_POINT_new(ecGroupFreePtr.get())};
        if (!EC_POINT_mul(ecGroupFreePtr.get(), pubKey.get(), bnPrivPtr.get(), nullptr, nullptr, nullptr)) {
            ThrowOpensslException("Failed to generate ec public key from EC_POINT_mul");
        }

        // Get the BIGNUM
        std::uint8_t* pubAsBigNum = nullptr;
        size_t bnLength = EC_POINT_point2buf(ecGroupFreePtr.get(),
                                            pubKey.get(),
                                             POINT_CONVERSION_COMPRESSED,
                                            &pubAsBigNum,
                                            nullptr);
        if (!bnLength) {
            ThrowOpensslException("Error obtaining the BIGNUM from EC_POINT.");
        }

        Openssl_buf_free_ptr opensslBufFreePtr{pubAsBigNum};
        auto bytes = gsl::make_span(pubAsBigNum, bnLength);
        return GetPEMPublicKeyFromECPoint(toBytes(bytes), curveName);
    }

    std::string ECKeyPair::GetPEMPublicKeyFromX509Cert(const std::string& pemKeyInX509) {

        if (boost::contains(pemKeyInX509, kX509CertTag)) {

            BIO_free_ptr pubBio{BIO_new(BIO_s_mem())};
            if ((size_t)BIO_write(pubBio.get(), pemKeyInX509.data(), pemKeyInX509.size()) != pemKeyInX509.size()) {
                ThrowOpensslException("Failed to load public key.");
            }

            X509_free_ptr x509Ptr{ PEM_read_bio_X509(pubBio.get(), NULL, NULL, NULL) };
            if (!x509Ptr) {
                ThrowOpensslException("Failed to create X509 cert struct.");
            }

            EVP_PKEY_free_ptr evppkeyPtr { X509_get_pubkey(x509Ptr.get()) };
            if (!evppkeyPtr) {
                ThrowOpensslException("Failed to create EVP_PKEY.");
            }

            BIO_free_ptr bio{BIO_new(BIO_s_mem())};

            if (1 != PEM_write_bio_PUBKEY(bio.get(), evppkeyPtr.get())) {
                ThrowOpensslException("Error writing EC public key data in PEM format.");
            }

            // Read the public key from the buffer and put it in the string
            std::string publicKeyPem(BIO_pending(bio.get()), '\0');
            auto readResult = BIO_read(bio.get(), publicKeyPem.data(), static_cast<int>(publicKeyPem.size()));
            if (readResult <= 0) {
                ThrowOpensslException("Failed to read public key data.");
            }

            return publicKeyPem;
        }

        return pemKeyInX509;
    }

    /// Calculate shared secret from public key from one party and the private key from another party.
    std::vector<gsl::byte> ECKeyPair::ComputeECDHKey(const std::string& publicKeyInPEM,
            const std::string& privateKeyInPEM) {

        // https://www.openssl.org/docs/man3.0/man7/EVP_KEYEXCH-ECDH.html
        if (publicKeyInPEM.empty() || privateKeyInPEM.empty()) {
            ThrowException("Invalid data to calculate the share secret.");
        }

        ///
        /// Extract public key
        ///
        EVP_PKEY_free_ptr ecPub = getECPublicKey(publicKeyInPEM);
        if (!ecPub) {
            ThrowOpensslException("Error generating EC key from public key.");
        }

        ///
        /// Extract private key
        ///
        BIO_free_ptr preBio{BIO_new(BIO_s_mem())};
        if ((size_t)BIO_write(preBio.get(), privateKeyInPEM.data(), privateKeyInPEM.size()) != privateKeyInPEM.size()) {
            ThrowOpensslException("Failed to load private key.");
        }

        EVP_PKEY_free_ptr ecPre {PEM_read_bio_PrivateKey(preBio.get(), nullptr, nullptr, nullptr)};
        if (!ecPre) {
            ThrowOpensslException("Failed to ec key from private key");
        }

        EVP_PKEY_CTX_free_ptr evpPrekeyCtxPtr { EVP_PKEY_CTX_new(ecPre.get(), nullptr)};
        if (!evpPrekeyCtxPtr) {
            ThrowOpensslException("Failed to create EVP_PKEY_CTX.");
        }

        if (1 != EVP_PKEY_private_check(evpPrekeyCtxPtr.get())) {
            ThrowOpensslException("Failed the sanity check for ec private key");
        }

        auto result = EVP_PKEY_derive_init(evpPrekeyCtxPtr.get());
        if(result <= 0){
            ThrowOpensslException("Failed to initialize the ECDH derive function.");
        }

        // NOTE: If the padding is required we need to enable this code.
        // OSSL_PARAM params[2];
        // unsigned int pad = 1;
        // params[0] = OSSL_PARAM_construct_uint(OSSL_EXCHANGE_PARAM_PAD, &pad);
        // params[1] = OSSL_PARAM_construct_end();
        // EVP_PKEY_CTX_set_params(evpPrekeyCtxPtr.get(), params);

        result = EVP_PKEY_derive_set_peer(evpPrekeyCtxPtr.get(), ecPub.get());
        if(result <= 0){
            ThrowOpensslException("Failed to initialize the peer for calculating the ECDH.");
        }

        std::vector<gsl::byte> symmetricKey;

        /* Get the size by passing NULL as the buffer */
        size_t secret_len{};
        result = EVP_PKEY_derive(evpPrekeyCtxPtr.get(), NULL, &secret_len);
        if(result <= 0){
            ThrowOpensslException("Failed to calculate the length of ECDH signature.");
        }

        symmetricKey.resize(secret_len);

        result = EVP_PKEY_derive(evpPrekeyCtxPtr.get(),
                                 reinterpret_cast<std::uint8_t*>(symmetricKey.data()),
                                 &secret_len);
        if(result <= 0){
            ThrowOpensslException("Failed to calculate the ECDH.");
        }

        return symmetricKey;
    }

    /// Return the compressed EC point for the public key.
    std::vector<gsl::byte> ECKeyPair::CompressedECPublicKey(const std::string& publicKeyInPEM) {

        // Info-https://www.openssl.org/docs/manmaster/man7/EVP_PKEY-EC.html
        // https://github.com/openssl/openssl/blob/1751356267f64d5db8824cf4ff5b3496e15972da/test/evp_pkey_provided_test.c

        ///
        /// Extract public key
        ///
        EVP_PKEY_free_ptr ecPub = getECPublicKey(publicKeyInPEM);
        if (!ecPub) {
            ThrowOpensslException("Error generating EC key from public key.");
        }

        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                                     OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED,
                                                      sizeof(OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED));
        params[1] = OSSL_PARAM_construct_end();
        auto result = EVP_PKEY_set_params(ecPub.get(), params);
        if(!result){
            ThrowOpensslException("Failed to get the length of ECPOINT from ec key.");
        }

        size_t len{};
        result =  EVP_PKEY_get_octet_string_param(ecPub.get(),
                                                       OSSL_PKEY_PARAM_PUB_KEY,
                                                       nullptr,
                                                       0,
                                                       &len);
        if(!result){
            ThrowOpensslException("Failed to get the length of ECPOINT from ec key.");
        }


        std::vector<gsl::byte> ecpoint(len);
        result =  EVP_PKEY_get_octet_string_param(ecPub.get(),
                                                  OSSL_PKEY_PARAM_PUB_KEY,
                                                  reinterpret_cast<std::uint8_t*>(ecpoint.data()),
                                                  ecpoint.size(),
                                                  &len);
        if(!result){
            ThrowOpensslException("Failed to get the curve name from ec key.");
        }

        return  ecpoint;
    }

    /// Return Public key in PEM format from compressed EC Point.
    std::string ECKeyPair::GetPEMPublicKeyFromECPoint(Bytes compressedECPoint, const std::string& curveName) {

        // Create a OSSL_PARAM_BLD structure to create EC key with public key
        OSSL_PARAM_BLD_free_ptr paramBldFreePtr {OSSL_PARAM_BLD_new()};
        if (!paramBldFreePtr){
            ThrowOpensslException("Error creating OSSL_PARAM_BLD structure.");
        }

        auto result = OSSL_PARAM_BLD_push_utf8_string(paramBldFreePtr.get(),
                                                      OSSL_PKEY_PARAM_GROUP_NAME,
                                                      curveName.c_str(),
                                                      curveName.size());
        if(!result) {
            ThrowOpensslException("Error building OSSL_PARAM_BLD structure.");
        }


        result = OSSL_PARAM_BLD_push_octet_string(paramBldFreePtr.get(),
                                                  OSSL_PKEY_PARAM_PUB_KEY,
                                                  compressedECPoint.data(),
                                                  compressedECPoint.size());
        if(!result) {
            ThrowOpensslException("Error building OSSL_PARAM_BLD structure.");
        }

        OSSL_PARAM_free_ptr osslParamFreePtr {OSSL_PARAM_BLD_to_param(paramBldFreePtr.get())};
        if (!osslParamFreePtr) {
            ThrowOpensslException("Error creating OSSL_PARAM structure.");
        }

        EVP_PKEY_CTX_free_ptr evpPkeyCtxPtr {EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)};
        if (!evpPkeyCtxPtr) {
            ThrowOpensslException("Failed to create EVP_PKEY_CTX.");
        }

        result = EVP_PKEY_fromdata_init(evpPkeyCtxPtr.get());
        if(result <= 0) {
            ThrowOpensslException("Error initializing EVP_PKEY from OSSL_PARAM.");
        }

        EVP_PKEY* evpPubkey = nullptr;
        result = EVP_PKEY_fromdata(evpPkeyCtxPtr.get(),
                                   &evpPubkey,
                                   EVP_PKEY_PUBLIC_KEY,
                                   osslParamFreePtr.get());
        if(result <= 0) {
            ThrowOpensslException("Error building EVP_PKEY from OSSL_PARAM.");
        }

        EVP_PKEY_free_ptr ecPub{evpPubkey};
        BIO_free_ptr bio{BIO_new(BIO_s_mem())};

        if (1 != PEM_write_bio_PUBKEY(bio.get(), ecPub.get())) {
            ThrowOpensslException("Error writing EC public key data in PEM format.");
        }

        // Read the public key from the buffer and put it in the string
        std::string publicKeyPem(BIO_pending(bio.get()), '\0');
        auto readResult = BIO_read(bio.get(), publicKeyPem.data(), static_cast<int>(publicKeyPem.size()));
        if (readResult <= 0) {
            ThrowOpensslException("Failed to read public key data.");
        }

        return publicKeyPem;
    }

    /// Generate a key using key derivation function.
    std::vector<gsl::byte> ECKeyPair::calculateHKDF(Bytes salt, Bytes secret) {

        std::vector<gsl::byte> key(secret.size());

        EVP_PKEY_CTX_free_ptr evpPkeyCtxPtr { EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr)};
        if (!evpPkeyCtxPtr) {
            ThrowOpensslException("Failed to create EVP_PKEY_CTX.");
        }

        if (1 != EVP_PKEY_derive_init(evpPkeyCtxPtr.get())) {
            ThrowOpensslException("EVP_PKEY_derive_init failed");
        }

        if (1 != EVP_PKEY_CTX_set_hkdf_md(evpPkeyCtxPtr.get(), EVP_sha256())) {
            ThrowOpensslException("EVP_PKEY_CTX_set_hkdf_md failed");
        }

        if (1 != EVP_PKEY_CTX_set1_hkdf_salt(evpPkeyCtxPtr.get(),
                                             reinterpret_cast<const std::uint8_t*>(salt.data()),
                                             salt.size())) {
            ThrowOpensslException("EVP_PKEY_CTX_set1_hkdf_salt failed");
        }

        if (1 != EVP_PKEY_CTX_set1_hkdf_key(evpPkeyCtxPtr.get(),
                                            reinterpret_cast<const std::uint8_t*>(secret.data()),
                                            secret.size())) {
            ThrowOpensslException("EVP_PKEY_CTX_set1_hkdf_key failed");
        }

        if (1 != EVP_PKEY_CTX_add1_hkdf_info(evpPkeyCtxPtr.get(), nullptr, 0)) {
            ThrowOpensslException("EVP_PKEY_CTX_add1_hkdf_info failed");
        }

        size_t outlen = key.size();
        if (1 != EVP_PKEY_derive(evpPkeyCtxPtr.get(), reinterpret_cast<std::uint8_t*>(key.data()), &outlen)) {
            ThrowOpensslException("EVP_PKEY_derive failed");
        }

        key.resize(outlen);

        return key;
    }

    /// Compute ECDSA signature for the digest for the key-pair of the curve.
    std::vector<gsl::byte> ECKeyPair::ComputeECDSASig(Bytes digest, const std::string& privateKeyInPEM) {

        if (privateKeyInPEM.empty()) {
            ThrowException("Invalid data to compute the signature.");
        }

        BIO_free_ptr preBio{BIO_new(BIO_s_mem())};
        if ((size_t)BIO_write(preBio.get(), privateKeyInPEM.data(), privateKeyInPEM.size()) != privateKeyInPEM.size()) {
            ThrowOpensslException("Failed to load private key.");
        }

        EVP_PKEY_free_ptr ecKey {PEM_read_bio_PrivateKey(preBio.get(), nullptr, nullptr, nullptr)};
        if (!ecKey) {
            ThrowOpensslException("Failed to read ec private key from pem format");
        }

        EVP_PKEY_CTX_free_ptr evpPkeyCtxPtr { EVP_PKEY_CTX_new(ecKey.get(), nullptr)};
        if (!evpPkeyCtxPtr) {
            ThrowOpensslException("Failed to create EVP_PKEY_CTX.");
        }

        if (1 != EVP_PKEY_private_check(evpPkeyCtxPtr.get())) {
            ThrowOpensslException("Failed the sanity check for ec private key");
        }

        EVP_MD_CTX_free_ptr mdCtxFreePtr { EVP_MD_CTX_new()};
        if (!mdCtxFreePtr) {
            ThrowOpensslException("Failed to create EVP_MD_CTX.");
        }

        size_t sigLength = EVP_PKEY_get_size(ecKey.get());
        std::vector<std::uint8_t> signature(sigLength);

        auto result = EVP_DigestSignInit_ex(mdCtxFreePtr.get(),
                                            nullptr,
                                            SHA2_256, nullptr, nullptr,
                                            ecKey.get(), nullptr);
        if (!result)  {
            ThrowOpensslException("Error initializing signing context, EVP_DigestSignInit_ex.");
        }


        result = EVP_DigestSign(mdCtxFreePtr.get(),
                                signature.data(),
                                &sigLength,
                                reinterpret_cast<const uint8_t*>(digest.data()),
                                digest.size());
        if (!result) {
            ThrowOpensslException("Error generating the signature EVP_DigestSign.");;
        }

        signature.resize(sigLength);

        const unsigned char *sigPtr = signature.data();
        ECDSASig_free_ptr ecdsaSigFreePtr{d2i_ECDSA_SIG(nullptr,
                                                        &sigPtr,
                                                        sigLength)};
        if (!ecdsaSigFreePtr) {
            ThrowOpensslException("Error decodes a DER encoded ECDSA signature, d2i_ECDSA_SIG");
        }

        auto keySize = getKeySizeForPkey(ecKey.get());

        auto rLength = BN_num_bytes(ECDSA_SIG_get0_r(ecdsaSigFreePtr.get()));
        auto sLength = BN_num_bytes(ECDSA_SIG_get0_s(ecdsaSigFreePtr.get()));

        ECSDASignature ecsdaSignature;
        ecsdaSignature.rLength = rLength;
        ecsdaSignature.sLength = sLength;
        ecsdaSignature.rValue.resize(keySize);
        ecsdaSignature.sValue.resize(keySize);

        // Add 'r' to signature
        result =  BN_bn2binpad(ECDSA_SIG_get0_r(ecdsaSigFreePtr.get()),
                               reinterpret_cast<uint8_t*>(ecsdaSignature.rValue.data()),  ecsdaSignature.rLength);
        if (result == -1) {
            ThrowOpensslException("Error converting BIGNUM to big endian - BN_bn2bin_padded()");
        }

        // Add 's' to signature
        result =  BN_bn2binpad(ECDSA_SIG_get0_s(ecdsaSigFreePtr.get()),
                               reinterpret_cast<uint8_t*>(ecsdaSignature.sValue.data()), ecsdaSignature.sLength);
        if (result == -1) {
            ThrowOpensslException("Error converting BIGNUM to big endian - BN_bn2bin_padded()");
        }

        return ECKeyPair::ecdsaSignatureAsBytes(ecsdaSignature);
    }

    /// Verify the signature for the digest for the key-pair of the curve.
    bool ECKeyPair::VerifyECDSASignature(Bytes digest, Bytes signature, const std::string& publicKeyInPEM) {

        if (publicKeyInPEM.empty()) {
            ThrowException("Invalid data to compute the signature.");
        }

        ///
        /// Extract public key
        ///
        EVP_PKEY_free_ptr ecPub = getECPublicKey(publicKeyInPEM);
        if (!ecPub) {
            ThrowOpensslException("Failed to create EVP_PKEY from public pem.");
        }

        ECDSASig_free_ptr ecdsaSigFreePtr(ECDSA_SIG_new());
        if (!ecdsaSigFreePtr) {
            ThrowOpensslException("Error creating ECDSA_SIG");
        }

        auto keySize = getKeySizeForPkey(ecPub.get());

        BIGNUM_free_ptr rBigNum(BN_new());
        BIGNUM_free_ptr sBigNum(BN_new());

        auto sigAsStruct = ecdsaSignatureAsStruct(signature, keySize);

        auto rLength = sigAsStruct.rLength;
        auto sLength = sigAsStruct.sLength;

        if (!BN_bin2bn(reinterpret_cast<const uint8_t*>(sigAsStruct.rValue.data()), rLength, rBigNum.get()) ||
            !BN_bin2bn(reinterpret_cast<const uint8_t*>(sigAsStruct.sValue.data()), sLength, sBigNum.get())) {
            ThrowOpensslException("Error converting from big endian - BN_bin2bn()");
        }

        auto result = ECDSA_SIG_set0(ecdsaSigFreePtr.get(), rBigNum.release(), sBigNum.release());
        if (!result) {
            ThrowOpensslException("Error constructing ECDSA_SIG");
        }

        auto sigLength = i2d_ECDSA_SIG(ecdsaSigFreePtr.get(), nullptr);
        if (sigLength < 0){
            ThrowOpensslException("Failed to calculate the length of ECDSA signature.");
        }

        std::vector<std::uint8_t> uncompressedSig(sigLength);
        unsigned char * sigPtr = uncompressedSig.data();
        sigLength = i2d_ECDSA_SIG(ecdsaSigFreePtr.get(), &sigPtr);
        if (sigLength < 0){
            ThrowOpensslException("Failed to calculate the length of ECDSA signature.");
        }

        // Rest the size.
        uncompressedSig.resize(sigLength);

        EVP_MD_CTX_free_ptr mdCtxFreePtr { EVP_MD_CTX_new()};
        if (!mdCtxFreePtr) {
            ThrowOpensslException("Failed to create EVP_MD_CTX.");
        }

        result = EVP_DigestVerifyInit_ex(mdCtxFreePtr.get(),
                                         nullptr,
                                         SHA2_256,
                                         nullptr,
                                         nullptr,
                                         ecPub.get(),
                                         nullptr);
        if (!result)  {
            ThrowOpensslException("Error initializing signing context, EVP_DigestVerifyInit_ex.");
        }

        result = EVP_DigestVerify(mdCtxFreePtr.get(),
                                 reinterpret_cast<const uint8_t*>(uncompressedSig.data()),
                                  sigLength,
                                 reinterpret_cast<const uint8_t*>(digest.data()),
                                 digest.size());

        return (result == 1);
    }

    /// Retrieve EC_KEY from pem formatted public key.
    EVP_PKEY_free_ptr ECKeyPair::getECPublicKey(const std::string& publicKey){

        EVP_PKEY_free_ptr publicKeyPtr;
        BIO_free_ptr publicKeyBuffer { BIO_new_mem_buf(publicKey.data(), publicKey.size()) };

        if (!publicKeyBuffer) {
            ThrowOpensslException("Failed to allocate memory for public key.");
        }

        if (boost::contains(publicKey, kX509CertTag)) {

            X509_free_ptr x509Ptr{ PEM_read_bio_X509(publicKeyBuffer.get(),
                                                     nullptr,
                                                     nullptr,
                                                     nullptr) };
            if (!x509Ptr) {
                ThrowOpensslException("Failed to create X509 cert struct.");
            }

            // Store the public key into EVP_PKEY
            publicKeyPtr.reset(X509_get_pubkey(x509Ptr.get()));

        } else {
            // Store the public key into RSA struct
            publicKeyPtr.reset(PEM_read_bio_PUBKEY(publicKeyBuffer.get(), nullptr, nullptr, nullptr));
        }

        if (!publicKeyPtr) {
            ThrowOpensslException("Failed to create a public key.");
        }

        EVP_PKEY_CTX_free_ptr evpPkeyCtxPtr { EVP_PKEY_CTX_new(publicKeyPtr.get(), nullptr)};
        if (!evpPkeyCtxPtr) {
            ThrowOpensslException("Failed to create EVP_PKEY_CTX.");
        }

        if (1 != EVP_PKEY_public_check(evpPkeyCtxPtr.get())) {
            ThrowOpensslException("Failed ec key(public) sanity check.");
        }

        return publicKeyPtr;
    }

    /// Return ECDSA signature as byte array
    /// The format - <rLength><rvalue><sLength><svalue>
    std::vector<gsl::byte> ECKeyPair::ecdsaSignatureAsBytes(ECSDASignature signature) {
        std::vector<std::byte> sigBuffer(sizeof(signature.rLength) + sizeof(signature.sLength) + signature.rValue.size() + signature.sValue.size());

        auto sigAsBytes = toWriteableBytes(sigBuffer);

        // Copy value of rLength
        auto index = 0;
        std::memcpy(sigAsBytes.data() + index, &signature.rLength, sizeof(signature.rLength));

        // Copy the contents of rValue
        index += sizeof(signature.rLength);
        std::memcpy(sigAsBytes.data() + index, signature.rValue.data(), signature.rValue.size());

        // Copy value of sLength
        index += signature.rValue.size();
        std::memcpy(sigAsBytes.data() + index, &signature.sLength, sizeof(signature.sLength));

        // Copy value of sValue
        index += sizeof(signature.sLength);
        std::memcpy(sigAsBytes.data() + index, signature.sValue.data(), signature.sValue.size());

        return sigBuffer;
    }

    /// Return ECDSA signature as struct from bytes array
    ECSDASignature ECKeyPair::ecdsaSignatureAsStruct(Bytes signatureBytes, std::uint8_t keySize) {
        ECSDASignature signature;

        // NOTE: The extra 2 bytes is for holding the length 'r' and 's' length
        if (signatureBytes.size() != (2 * keySize) + 2) {
            ThrowException("Invalid signature buffer size");
        }

        // Copy value of rLength to signature struct
        auto index = 0;
        std::memcpy(&signature.rLength, signatureBytes.data() + index, sizeof(signature.rLength));

        // Copy the contents of rValue to signature struct
        index += sizeof(signature.rLength);
        signature.rValue.resize(keySize);
        std::memcpy(signature.rValue.data(), signatureBytes.data() + index, signature.rLength);

        // Copy value of sLength to signature struct
        index += keySize;
        std::memcpy(&signature.sLength, signatureBytes.data() + index, sizeof(signature.sLength));

        // Copy value of sValue
        index += sizeof(signature.sLength);
        signature.sValue.resize(keySize);
        std::memcpy(signature.sValue.data(), signatureBytes.data() + index, signature.sLength);

        return signature;
    }

    /// Return the size of key of the given curve.
    std::uint8_t ECKeyPair::getECKeySize(const std::string curveName) {
        if (boost::iequals(curveName, SECP256R1_CURVE) ||
            boost::iequals(curveName, PRIME256V1_CURVE)) {
            return 32;
        } else if (boost::iequals(curveName, SECP384R1_CURVE)) {
            return 48;
        } else if (boost::iequals(curveName, SECP521R1_CURVE)) {
            return 66;
        } else {
            ThrowException("Unsupported ECC algorithm.", VIRTRU_CRYPTO_ERROR);
        }

        return 0;
    }

    /// Return the key size given the EC Key
    /// \param pKey - EC Key
    /// \return Size of the EC key
    std::uint8_t ECKeyPair::getKeySizeForPkey(EVP_PKEY* pKey) {
        size_t len{};
        auto result =  EVP_PKEY_get_utf8_string_param(pKey,
                                                      OSSL_PKEY_PARAM_GROUP_NAME,
                                                      nullptr,
                                                      0,
                                                      &len);
        if(!result){
            ThrowOpensslException("Failed to get the length of curve name from ec key.");
        }


        std::string curveName(len+1, '0');
        result =  EVP_PKEY_get_utf8_string_param(pKey,
                                                 OSSL_PKEY_PARAM_GROUP_NAME,
                                                 curveName.data(),
                                                 curveName.size(),
                                                 &len);
        if(!result){
            ThrowOpensslException("Failed to get the curve name from ec key.");
        };

        curveName.resize(len);
        std::string curve(curveName);

        return getECKeySize(curveName);
    }


}  // namespace virtru::crypto
