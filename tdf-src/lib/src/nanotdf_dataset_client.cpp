//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/09/24
//  Copyright 2020 Virtru Corporation
//

#include <cinttypes>

#include <memory>
#include "crypto/ec_key_pair.h"
#include "network_interface.h"
#include "nanotdf.h"
#include "nanotdf_builder.h"
#include "nanotdf_builder_impl.h"
#include "nanotdf_client.h"
#include "nanotdf_dataset_client.h"

namespace virtru {

    /// Constructs a nano TDF client instance.
    /// NOTE: should me used for only offline decrypt operation.
    NanoTDFDatasetClient::NanoTDFDatasetClient(uint32_t maxKeyIterations)
        : NanoTDFDatasetClient("http://eas", "NO_OWNER", "",
                "", "", maxKeyIterations) {
        m_offline = true;

    }

    /// Constructor
    NanoTDFDatasetClient::NanoTDFDatasetClient(const std::string& easUrl,
            const std::string& user, uint32_t maxKeyIterations)
            : NanoTDFDatasetClient(easUrl, user, "", "",
                    "", maxKeyIterations) {

    }

    /// Constructor
    NanoTDFDatasetClient::NanoTDFDatasetClient(const std::string& easUrl, const std::string& user,
                                 const std::string& clientKeyFileName, const std::string& clientCertFileName,
                                 const std::string& sdkConsumerCertAuthority, uint32_t maxKeyIterations)
                                 :m_MaxKeyIterations(maxKeyIterations) {

        m_nanoTdfClient = std::make_unique<NanoTDFClient>(easUrl, user, clientKeyFileName,
                clientCertFileName, sdkConsumerCertAuthority);

        m_nanoTdfClient->m_nanoTdfBuilder->setOffline(m_offline);

        m_nanoTdfClient->initNanoTDFBuilder();
    }

    /// Destructor
    NanoTDFDatasetClient::~NanoTDFDatasetClient() = default;

    /// Encrypt the file to nano tdf format.
    void NanoTDFDatasetClient::encryptFile(const std::string& inFilepath, const std::string& outFilepath) {

        initializeNanoTDF();

        m_nanoTdf->encryptFile(inFilepath, outFilepath);
    }

    /// Encrypt the data to nano tdf format.
    std::string_view NanoTDFDatasetClient::encryptString(const std::string &plainData) {

        initializeNanoTDF();

        return m_nanoTdf->encryptString(plainData);
    }

    /// Decrypt file.
    void NanoTDFDatasetClient::decryptFile(const std::string& inFilepath, const std::string& outFilepath) {

        initializeNanoTDF();

        checkEntityObject();

        m_nanoTdf->decryptFile(inFilepath, outFilepath);
    }

    /// Decrypt data from nano tdf format.
    std::string_view NanoTDFDatasetClient::decryptString(const std::string& encryptedData) {

        initializeNanoTDF();

        checkEntityObject();

        return std::string_view{m_nanoTdf->decryptString(encryptedData)};
    }

    /// Enable the internal logger class to write logs to the console for given LogLevel.
    void NanoTDFDatasetClient::enableConsoleLogging(LogLevel logLevel) {
        m_nanoTdfClient->m_nanoTdfBuilder->enableConsoleLogging(logLevel);
    }

    /// Add access to the TDF file/data for the users in the list
    void NanoTDFDatasetClient::shareWithUsers(const std::vector<std::string>& users) {
        m_nanoTdfClient->shareWithUsers(users);
    }

    /// Allow user to read entity attributes
    std::vector<std::string> NanoTDFDatasetClient::getEntityAttributes() {
        return m_nanoTdfClient->getEntityAttributes();
    }

    /// Allow user to add data attributes
    void NanoTDFDatasetClient::withDataAttributes(const std::vector<std::string>& dataAttributes) {
        m_nanoTdfClient->withDataAttributes(dataAttributes);
    }

    ///Allow user to read data attributes associated with this instances of client (to be replaced by inspectDataAttributes)
    std::vector<std::string> NanoTDFDatasetClient::getDataAttributes() {
        return m_nanoTdfClient->getDataAttributes();
    }

    /// Set the entity private key(In PEM format), which will be used by this SDK for encryption/decryption of
    /// the payload/policy. The private key should be from one of predefined curves defined in tdf_constants.h
    void NanoTDFDatasetClient::setEntityPrivateKey(const std::string& privateKey, EllipticCurve curve) {
        m_nanoTdfClient->setEntityPrivateKey(privateKey, curve);
    }

    /// Set the signer private key(In PEM format). Calling this method enables the signature entry in nano tdf
    /// The ECC private key should be from one of predefined curves which are defined in tdf_constants.h
    void NanoTDFDatasetClient::setSignerPrivateKey(const std::string& signerPrivateKey, EllipticCurve curve) {
        m_nanoTdfClient->setSignerPrivateKey(signerPrivateKey, curve);
    }

    /// Set the kas public key(In PEM format). This can be used for offline mode.
    void NanoTDFDatasetClient::setDecrypterPublicKey(const std::string& decrypterPublicKey) {
        m_nanoTdfClient->setDecrypterPublicKey(decrypterPublicKey);
    }

    /// Validate the TDF on decrypt(check if the TDF is singed by right entity). Throws exception
    /// on decrypt if the given public key doesn't match the one in TDF.
    void NanoTDFDatasetClient::validateSignature(const std::string& signerPublicKey) {
        m_nanoTdfClient->validateSignature(signerPublicKey);
    }

    /// Return the entity private key in PEM format and the curve of the key.
    /// \return - The entity private key in PEM format and the curve of the key.
    std::pair<std::string, std::string> NanoTDFDatasetClient::getEntityPrivateKeyAndCurve() const {
        return m_nanoTdfClient->getEntityPrivateKeyAndCurve();
    }

    // Initialize the NanoTDF
    void NanoTDFDatasetClient::initializeNanoTDF() {
        if (!m_nanoTdf) {
            // Create a policy object.
            auto policyObject = m_nanoTdfClient->createPolicyObject();
            m_nanoTdf = m_nanoTdfClient->m_nanoTdfBuilder->setPolicyObject(policyObject).buildNanoTDFDataset(m_MaxKeyIterations);
        }
    }

    // Check if the EO needs to updated.
    void NanoTDFDatasetClient::checkEntityObject() {
        auto impl = m_nanoTdfClient->m_nanoTdfBuilder->m_impl.get();
        if (impl->m_publicKey != impl->m_entityObject.getPublicKey() && !impl->m_offlineMode) {
            LogInfo("Updating entity object");
            m_nanoTdfClient->fetchEntityObject();
        }
    }
}
