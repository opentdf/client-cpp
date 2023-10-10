/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/02.
//

#include "openssl_deleters.h"
#include "bytes.h"

#include <string>

#ifndef VIRTRU_RSA_KEY_PAIR_H
#define VIRTRU_RSA_KEY_PAIR_H

namespace virtru::crypto {

    // Generate a key pair and provides an interface for returning the keys in PEM format.
    class RsaKeyPair {
    public: // Interface

        /// Creates an instance of RsaKeyPair and will generate a new key pair every time it is called.
        /// \param keySize - The key size(default is 2048 bits).
        /// \return Unique ptr of the instance.
        static std::unique_ptr<RsaKeyPair> Generate(unsigned keySize = 2048);

        /// Return public key in PEM format.
        /// \return string - In PEM format.
        std::string PublicKeyInPEMFormat() const;

        /// Return private key in PEM format.
        /// \return string - In PEM format.
        std::string PrivateKeyInPEMFormat() const;

        // Not supported.
        RsaKeyPair(const RsaKeyPair &) = delete;
        RsaKeyPair(RsaKeyPair &&) = delete;
        RsaKeyPair & operator=(const RsaKeyPair &) = delete;
        RsaKeyPair & operator=(RsaKeyPair &&) = delete;

    public: /// Helper methods.

        /// Compute RSA signature for the digest for the private key.
        /// \param digest - The digest for which the signature to be computed.
        /// \param privateKeyInPEM - The private key in PEM format.
        /// \return Signature - The signature
        static std::vector<gsl::byte> ComputeRSASig(Bytes digest,
                                                    const std::string& privateKeyInPEM);

        /// Verify the signature for the digest for the public-key.
        /// \param digest - The digest for which the signature to be computed.
        /// \param signature - The signature for the digest.
        /// \param publicKeyInPEM - The public key in PEM format.
        /// \return True if the signature is valid.
        static bool VerifyERSASignature(Bytes digest,
                                        Bytes signature,
                                        const std::string& publicKeyInPEM);

    private:
        explicit RsaKeyPair(EVP_PKEY_free_ptr rsa);

        // Data
        EVP_PKEY_free_ptr m_rsa;
    };
}  // namespace virtru::crypto


#endif //VIRTRU_RSA_KEY_PAIR_H
