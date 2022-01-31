/*
* Copyright 2020 Virtru Corporation
*
* SPDX - License - Identifier: MIT
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/04/20.
//


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

namespace virtru::crypto {

    /// Constants
    constexpr auto kX509CertTag = "BEGIN CERTIFICATE";

    /// Constructor
    ECKeyPair::ECKeyPair(EVP_PKEY_free_ptr pkey)
        : m_pkey(std::move(pkey)) {}

    /// Creates an instance of EC(Elliptic Curve) Key and will generate a new key pair every time it is called.
    std::unique_ptr<ECKeyPair> ECKeyPair::Generate(const std::string& curveName) {

        auto eccgrp = OBJ_txt2nid(curveName.data());
        if (eccgrp == NID_undef) {
            ThrowOpensslException("Unknown curve name.");
        }

        EC_free_ptr ec{EC_KEY_new_by_curve_name(eccgrp)};

        // Create the public/private EC key pair here
        if (1 != EC_KEY_generate_key(ec.get())) {
            ThrowOpensslException("Failed ECKeyPair generation.");
        }

        if (1 != EC_KEY_check_key(ec.get())) {
            ThrowOpensslException("Failed EC sanity check.");
        }

        EVP_PKEY_free_ptr evppkeyPtr { EVP_PKEY_new()};
        if (1 != EVP_PKEY_assign_EC_KEY(evppkeyPtr.get(), ec.release())) {
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

        if (1 != PEM_write_bio_PrivateKey(bio.get(), m_pkey.get(), nullptr,
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
        auto ec = EVP_PKEY_get0_EC_KEY(m_pkey.get());
        auto ecGroup =  EC_KEY_get0_group(ec);

        auto curveName = OBJ_nid2sn(EC_GROUP_get_curve_name(ecGroup));
        if (curveName == nullptr) {
            ThrowOpensslException("Failed to get the curve name from ec key.");
        }

        return curveName;
    }

    /// Generate a public key given the private key and it's curve.
    std::string ECKeyPair::GetPEMPublicKeyFromPrivateKey(const std::string& privateKeyInPEM,
                                                     const std::string& curveName) {

        // Create a group give the curve name.
        auto eccgrp = OBJ_txt2nid(curveName.data());
        if (eccgrp == NID_undef) {
            ThrowOpensslException("Unknown curve name.");
        }

        EC_free_ptr ec{EC_KEY_new_by_curve_name(eccgrp)};
        auto group = EC_KEY_get0_group(ec.get());

        /// Extract private key as big number from the pem formatted private key
        BIO_free_ptr preBio{BIO_new(BIO_s_mem())};
        if ((size_t)BIO_write(preBio.get(), privateKeyInPEM.data(), privateKeyInPEM.size()) != privateKeyInPEM.size()) {
            ThrowOpensslException("Failed to load private key.");
        }

        EC_free_ptr ecPre {PEM_read_bio_ECPrivateKey(preBio.get(), nullptr, nullptr, nullptr)};
        if (!ecPre) {
            ThrowOpensslException("Failed to read ec private key from pem format");
        }

        if (1 != EC_KEY_check_key(ecPre.get())) {
            ThrowOpensslException("Failed the sanity check for ec private key");
        }

        auto bigNum = EC_KEY_get0_private_key(ecPre.get());
        if (!bigNum) {
            ThrowOpensslException("Failed get a BIGNUM from ec private key.");
        }

        // Set the private key to ec key        ;
        if (1 != EC_KEY_set_private_key(ec.get(), bigNum)) {
            ThrowOpensslException("Failed to set the private key to ec key");
        }

        // Create a ECPoint and generate a public key.
        ECPoint_free_ptr pubKey{EC_POINT_new(group)};
        if (!EC_POINT_mul(group, pubKey.get(), bigNum, nullptr, nullptr, nullptr)) {
            ThrowOpensslException("Failed to generate ec public key from EC_POINT_mul");
        }

        // Set the public key to ec key        ;
        if (1 !=  EC_KEY_set_public_key(ec.get(), pubKey.get())) {
            ThrowOpensslException("Failed to set the public key to ec key");
        }


        EVP_PKEY_free_ptr evppkeyPtr { EVP_PKEY_new()};
        if (1 != EVP_PKEY_assign_EC_KEY(evppkeyPtr.get(), ec.release())) {
            ThrowOpensslException("Error assigning EC key to EVP_PKEY structure.");
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

    std::string ECKeyPair::GetPEMPublicKeyFromX509Cert(const std::string& pemKeyInX509) {

        if (boost::contains(pemKeyInX509, kX509CertTag)) {
            EC_free_ptr ecPub;

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

        if (publicKeyInPEM.empty() || privateKeyInPEM.empty()) {
            ThrowException("Invalid data to calculate the share secret.");
        }

        ///
        /// Extract public key
        ///
        EC_free_ptr ecPub = getECPublicKey(publicKeyInPEM);

        ///
        /// Extract private key
        ///
        BIO_free_ptr preBio{BIO_new(BIO_s_mem())};
        if ((size_t)BIO_write(preBio.get(), privateKeyInPEM.data(), privateKeyInPEM.size()) != privateKeyInPEM.size()) {
            ThrowOpensslException("Failed to load private key.");
        }

        EC_free_ptr ecPre {PEM_read_bio_ECPrivateKey(preBio.get(), nullptr, nullptr, nullptr)};
        if (!ecPre) {
            ThrowOpensslException("Failed to ec key from private key");
        }

        if (1 != EC_KEY_check_key(ecPre.get())) {
            ThrowOpensslException("Failed ec key(private) sanity check.");
        }

        /// Calculate shared secret length.
        std::vector<gsl::byte> symmetricKey;
        auto secretLen = EC_GROUP_get_degree(EC_KEY_get0_group(ecPre.get()));
        secretLen = (secretLen + 7) / 8;
        symmetricKey.resize(secretLen);

        auto pubkey  = EC_KEY_get0_public_key(ecPub.get());
        if (ECDH_compute_key(symmetricKey.data(), symmetricKey.size(), pubkey, ecPre.get(), nullptr) == -1) {
            ThrowOpensslException("Failed to compute ECDH key.");
        }

        return symmetricKey;
    }

    /// Return the compressed EC point for the public key.
    std::vector<gsl::byte> ECKeyPair::CompressedECPublicKey(const std::string& publicKeyInPEM) {

        ///
        /// Extract public key
        ///
        BIO_free_ptr pubBio{BIO_new(BIO_s_mem())};
        if ((size_t)BIO_write(pubBio.get(), publicKeyInPEM.data(), publicKeyInPEM.size()) != publicKeyInPEM.size()) {
            ThrowOpensslException("Failed to load public key.");
        }

        EC_free_ptr ecPub {PEM_read_bio_EC_PUBKEY(pubBio.get(), nullptr, nullptr, nullptr)};
        if (!ecPub) {
            ThrowOpensslException("Failed to ec key from public key");
        }

        if (1 != EC_KEY_check_key(ecPub.get())) {
            ThrowOpensslException("Failed ec key(public) sanity check.");
        }

        auto pubkey  = EC_KEY_get0_public_key(ecPub.get());
        auto group = EC_KEY_get0_group(ecPub.get());
        if (!pubkey || !group) {
            ThrowOpensslException("Failed to get ec publickey/group.");
        }

        /// Get the EC_POINT in compressed form.
        std::vector<gsl::byte> point;
        auto len = EC_POINT_point2oct(group, pubkey,POINT_CONVERSION_COMPRESSED, nullptr, 0, nullptr);
        if (len == 0) {
            ThrowOpensslException("Failed to get ec point.");
        }

        point.resize(len);
        if(EC_POINT_point2oct(group, pubkey, POINT_CONVERSION_COMPRESSED,
                              reinterpret_cast<std::uint8_t*>(point.data()), len, nullptr) != len) {
            ThrowOpensslException("Failed to get ec point.");
        }

        return point;
    }

    /// Return Public key in PEM format from compressed EC Point.
    std::string ECKeyPair::GetPEMPublicKeyFromECPoint(Bytes compressedECPoint, const std::string& curveName) {

        auto eccgrp = OBJ_txt2nid(curveName.data());
        if (eccgrp == NID_undef) {
            ThrowOpensslException("Unknown curve name.");
        }

        EC_free_ptr ec{EC_KEY_new_by_curve_name(eccgrp)};
        auto group = EC_KEY_get0_group(ec.get());

        ECPoint_free_ptr ecPointFreePtr{EC_POINT_new(group)};

        auto retValue = EC_POINT_oct2point(group, ecPointFreePtr.get(),
                                      reinterpret_cast<const uint8_t *>(compressedECPoint.data()),
                                      compressedECPoint.size(), nullptr);
        if (retValue != 1) {
            ThrowOpensslException("Failed to get ec point from compressed point.");
        }

        retValue = EC_KEY_set_public_key(ec.get(), ecPointFreePtr.get());
        if (retValue != 1) {
            ThrowOpensslException("Failed to set public key.");
        }

        EVP_PKEY_free_ptr evppkeyPtr { EVP_PKEY_new()};
        if (1 != EVP_PKEY_assign_EC_KEY(evppkeyPtr.get(), ec.release())) {
            ThrowOpensslException("Error assigning EC key to EVP_PKEY structure.");
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

    /// Compute ECSDSA signature for the digest for the key-pair of the curve.
    std::vector<gsl::byte> ECKeyPair::ComputeECDSASig(Bytes digest, const std::string& privateKeyInPEM) {

        if (privateKeyInPEM.empty()) {
            ThrowException("Invalid data to compute the signature.");
        }

        BIO_free_ptr preBio{BIO_new(BIO_s_mem())};
        if ((size_t)BIO_write(preBio.get(), privateKeyInPEM.data(), privateKeyInPEM.size()) != privateKeyInPEM.size()) {
            ThrowOpensslException("Failed to load private key.");
        }

        EC_free_ptr ecKey {PEM_read_bio_ECPrivateKey(preBio.get(), nullptr, nullptr, nullptr)};
        if (!ecKey) {
            ThrowOpensslException("Failed to read ec private key from pem format");
        }

        if (1 != EC_KEY_check_key(ecKey.get())) {
            ThrowOpensslException("Failed the sanity check for ec private key");
        }

        ECDSASig_free_ptr ecdsaSigFreePtr(ECDSA_do_sign(reinterpret_cast<const uint8_t*>(digest.data()),
                                                        digest.size(), ecKey.get()));

        if (!ecdsaSigFreePtr) {
            ThrowOpensslException("Error generating the signature ECDSA_do_sign()");
        }

        // Calculate the size of the signature.
        auto group = EC_KEY_get0_group(ecKey.get());
        auto order = EC_GROUP_get0_order(group);
        auto bigNumLen = BN_num_bytes(order);
        auto sigLength = bigNumLen * 2;
        std::vector<gsl::byte> signature(sigLength);

        // Add 'r' to signature
        auto result =  BN_bn2binpad(ECDSA_SIG_get0_r(ecdsaSigFreePtr.get()),
                                    reinterpret_cast<uint8_t*>(signature.data()),  bigNumLen);
        if (!result) {
            ThrowOpensslException("Error converting BIGNUM to big endian - BN_bn2bin_padded()");
        }

        // Add 's' to signature
        result =  BN_bn2binpad(ECDSA_SIG_get0_s(ecdsaSigFreePtr.get()),
                               reinterpret_cast<uint8_t*>(signature.data() + bigNumLen), bigNumLen);
        if (!result) {
            ThrowOpensslException("Error converting BIGNUM to big endian - BN_bn2bin_padded()");
        }

        return signature;
    }

    /// Verify the signature for the digest for the key-pair of the curve.
    bool ECKeyPair::VerifyECDSASignature(Bytes digest, Bytes signature, const std::string& publicKeyInPEM) {

        if (publicKeyInPEM.empty()) {
            ThrowException("Invalid data to compute the signature.");
        }

        ///
        /// Extract public key
        ///
        EC_free_ptr ecPub = getECPublicKey(publicKeyInPEM);

        ECDSASig_free_ptr ecdsaSigFreePtr(ECDSA_SIG_new());
        if (!ecdsaSigFreePtr) {
            ThrowOpensslException("Error creating ECDSA_SIG");
        }

        BIGNUM_free_ptr rBigNum(BN_new());
        BIGNUM_free_ptr sBigNum(BN_new());

        auto sizeOfRAndS = (signature.size() / 2);

        if (!BN_bin2bn(reinterpret_cast<const uint8_t*>(signature.data()), sizeOfRAndS, rBigNum.get()) ||
            !BN_bin2bn(reinterpret_cast<const uint8_t*>(signature.data()+sizeOfRAndS), sizeOfRAndS, sBigNum.get())) {
            ThrowOpensslException("Error converting from big endian - BN_bin2bn()");
        }

        auto result = ECDSA_SIG_set0(ecdsaSigFreePtr.get(), rBigNum.release(), sBigNum.release());
        if (!result) {
            ThrowOpensslException("Error constructing ECDSA_SIG");
        }

        result = ECDSA_do_verify(reinterpret_cast<const uint8_t*>(digest.data()), digest.size(),
                                 ecdsaSigFreePtr.get(), ecPub.get());

        return (result == 1);
    }

    /// Retrieve EC_KEY from pem formatted public key.
    EC_free_ptr ECKeyPair::getECPublicKey(const std::string& publicKey){

        BIO_free_ptr pubBio{BIO_new(BIO_s_mem())};
        if ((size_t)BIO_write(pubBio.get(), publicKey.data(), publicKey.size()) != publicKey.size()) {
            ThrowOpensslException("Failed to load public key.");
        }

        EC_free_ptr ecPub;
        if (boost::contains(publicKey, kX509CertTag)) {

            X509_free_ptr x509Ptr{ PEM_read_bio_X509(pubBio.get(), NULL, NULL, NULL) };
            if (!x509Ptr) {
                ThrowOpensslException("Failed to create X509 cert struct.");
            }

            EVP_PKEY_free_ptr evppkeyPtr { X509_get_pubkey(x509Ptr.get()) };
            if (!evppkeyPtr) {
                ThrowOpensslException("Failed to create EVP_PKEY.");
            }

            ecPub.reset(EVP_PKEY_get1_EC_KEY(evppkeyPtr.get()));
            if (!ecPub) {
                ThrowOpensslException("Failed to ec key from public key");
            }
        } else {
            ecPub.reset(PEM_read_bio_EC_PUBKEY(pubBio.get(), nullptr, nullptr, nullptr));
            if (!ecPub) {
                ThrowOpensslException("Failed to ec key from public key");
            }
        }

        if (1 != EC_KEY_check_key(ecPub.get())) {
            ThrowOpensslException("Failed ec key(public) sanity check.");
        }

        return ecPub;
    }



}  // namespace virtru::crypto
