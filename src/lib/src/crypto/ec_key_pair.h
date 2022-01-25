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

#include "openssl_deleters.h"
#include "bytes.h"

#include <string>
#include <vector>

#ifndef VIRTRU_EC_KEY_PAIR_H
#define VIRTRU_EC_KEY_PAIR_H

namespace virtru::crypto {

    // Generate a key pair and provides an interface for returning the keys in PEM format.
    class ECKeyPair {
    public: /// Interface

        /// Creates an instance of EC(Elliptic Curve) Key and will generate a new key pair every time it is called.
        /// \param curveName - The named curve.
        /// \return Unique ptr of the instance.
        static std::unique_ptr<ECKeyPair> Generate(const std::string& curveName);

        /// Return public key in PEM format.
        /// \return string - In PEM format.
        std::string PublicKeyInPEMFormat() const;

        /// Return private key in PEM format.
        /// \return string - In PEM format.
        std::string PrivateKeyInPEMFormat() const;

        /// Return the key size in bits.
        unsigned int KeySize() const;

        /// Return the curve name.
        std::string CurveName() const;

        /// Not supported.
        ECKeyPair(const ECKeyPair &) = delete;
        ECKeyPair(ECKeyPair &&) = delete;
        ECKeyPair & operator=(const ECKeyPair &) = delete;
        ECKeyPair & operator=(ECKeyPair &&) = delete;

    public: /// Helper methods.
        /// Generate a public key given the private key and it's curve.
        /// \param privateKeyInPEM - PEM encoded private key.
        /// \param curveName - The elliptical curve name of the private key.
        /// \return Public key in PEM Format.
        static std::string GetPEMPublicKeyFromPrivateKey(const std::string& privateKeyInPEM,
                const std::string& curveName);

        /// Generate a public key in pem given the public key in X509 format.
        /// \param pemKeyInX509 - X509 cert.
        /// \return Public key in PEM Format.
        static std::string GetPEMPublicKeyFromX509Cert(const std::string& pemKeyInX509);

        /// Computes ECDH key from public key from one party and the private key from another party.
        /// \param publicKeyInPEM - Public key in PEM Format.
        /// \param privateKeyInPEM - Private key in PEM Format.
        /// \return symmetricKey - The symmetric key
        static std::vector<gsl::byte> ComputeECDHKey(const std::string& publicKeyInPEM,
                const std::string& privateKeyInPEM);

        /// Return the compressed EC point for the public key.
        /// \param publicKeyInPEM - Public key in PEM Format.
        /// \return point - Compressed EC point of for the public key.
        static std::vector<gsl::byte> CompressedECPublicKey(const std::string& publicKeyInPEM);

        /// Return Public key in PEM format from compressed EC Point.
        /// \param compressedECPoint - Compressed EC point
        /// \return PublicKey in PEM format.
        static std::string GetPEMPublicKeyFromECPoint(Bytes compressedECPoint, const std::string& curveName);

        /// Generate a key using key derivation function.
        /// \param salt - The salt which is used in key derivation function.
        /// \param secret - The secret which is used in key derivation function.
        /// \return Key - The generated key, same length as key.
        static std::vector<gsl::byte> calculateHKDF(Bytes salt, Bytes secret);

        /// Compute ECSDSA signature for the digest for the private key.
        /// NOTE: The signature contains (r concat s) stored in in big endian
        /// format. The r and s from ecdsa_sig_st
        /// \param digest - The digest for which the signature to be computed.
        /// \param privateKeyInPEM - The private key in PEM format.
        /// \return Signature - The signature
        static std::vector<gsl::byte> ComputeECDSASig(Bytes digest, const std::string& privateKeyInPEM);

        /// Verify the signature for the digest for the public-key.
        /// NOTE: This method expects the  signature to be (r concat s) stored in big endian
        /// format. The r and s from ecdsa_sig_st
        /// \param digest - The digest for which the signature to be computed.
        /// \param signature - The signature for the digest.
        /// \param publicKeyInPEM - The public key in PEM format.
        /// \return True if the signature is valid.
        static bool VerifyECDSASignature(Bytes digest, Bytes signature, const std::string& publicKeyInPEM);

    private:
        /// Retrieve EC_KEY from pem formatted public key.
        /// \param publicKeyInPEM - pem formatted key.
        /// \return EC_free_ptr unique ptr to EC_KEY instance.
        static EC_free_ptr getECPublicKey(const std::string& publicKey);

    private:
        /// Constructor
        /// \param pkey
        explicit ECKeyPair(EVP_PKEY_free_ptr pkey);

        // Data
        EVP_PKEY_free_ptr m_pkey;
    };
}

#endif //VIRTRU_EC_KEY_PAIR_H
