/*
 * Copyright 2022 Virtru Corporation
 *
 * SPDX - License Identifier: BSD-3-Clause-Clear
 *
 */

#include "logger.h"
#include "tdf_client.h"
#include "tdf_client_c.h"
#include "tdf_constants.h"

#include <algorithm>
#include <sstream>

#ifdef __cplusplus
extern "C" {
#endif

/// Hack to allow .NET P/Invoke to free native memory for a random pointer
/// \param vMemoryPtr - The malloc'd memory to be freed.
DLL_PUBLIC TDF_STATUS TDFFreeMemory(void *memoryPtr) {
    if (memoryPtr == nullptr) {
        return TDF_STATUS_INVALID_PARAMS;
    }

    try {
        free(memoryPtr);
        return TDF_STATUS_SUCCESS;
    } catch (std::exception &e) {
        LogError(e.what());
    } catch (...) {
        LogDefaultError();
    }
    return TDF_STATUS_FAILURE;
}

DLL_PUBLIC TDFCredsPtr TDFCreateCredentialPKI(const char *oidcEndpoint,
                                              const char *clientId,
                                              const char *clientKeyFileName,
                                              const char *clientCertFileName,
                                              const char *sdkConsumerCertAuthority,
                                              const char *organizationName) {

    auto *creds = new virtru::OIDCCredentials();
    creds->setClientCredentialsPKI(clientId, clientKeyFileName,
                                   clientCertFileName, sdkConsumerCertAuthority,
                                   organizationName, oidcEndpoint);

    return creds;
}

DLL_PUBLIC TDFCredsPtr TDFCreateCredentialClientCreds(const char *oidcEndpoint,
                                                      const char *clientId,
                                                      const char *clientSecret,
                                                      const char *organizationName) {
    auto *creds = new virtru::OIDCCredentials();
    creds->setClientCredentialsClientSecret(clientId, clientSecret,
                                            organizationName, oidcEndpoint);

    return creds;
}

DLL_PUBLIC TDFCredsPtr TDFCreateCredentialTokenExchange(const char *oidcEndpoint,
                                                        const char *clientId,
                                                        const char *clientSecret,
                                                        const char *externalExchangeToken,
                                                        const char *organizationName) {
    auto *creds = new virtru::OIDCCredentials();
    creds->setClientCredentialsTokenExchange(clientId, clientSecret, externalExchangeToken,
                                             organizationName, oidcEndpoint);

    return creds;
}

DLL_PUBLIC TDFStorageTypePtr TDFCreateTDFStorageFileType(const char *filePath) {
    auto *storageType = new virtru::TDFStorageType();
    storageType->setTDFStorageFileType(filePath);

    return storageType;
}

DLL_PUBLIC TDFStorageTypePtr TDFCreateTDFStorageStringType(TDFCBytesPtr inBytesPtr,
                                                           TDFBytesLength inBytesLength) {
    auto *storageType = new virtru::TDFStorageType();

    storageType->setTDFStorageStringType({reinterpret_cast<char const *>(inBytesPtr),
                                      inBytesLength});

    return storageType;
}

DLL_PUBLIC TDFStorageTypePtr TDFCreateTDFStorageS3Type(const char *S3Url,
                                                       const char *awsAccessKeyId,
                                                       const char *awsSecretAccessKey,
                                                       const char *awsRegionName) {
    auto *storageType = new virtru::TDFStorageType();
    storageType->setTDFStorageS3Type(S3Url, awsAccessKeyId, awsSecretAccessKey, awsRegionName);

    return storageType;
}

/// Destruct the credentials instance.
DLL_PUBLIC void TDFDestroyCredential(TDFCredsPtr creds) {
    auto *credsCast = static_cast<virtru::OIDCCredentials *>(creds);
    delete credsCast;
}

/// Create a new TDF client using provided credentials object
/// \param credsPtr - Creds object created by calling CreateCredentialXXX
/// \param kasURL - URL of a key access service
DLL_PUBLIC TDFClientPtr TDFCreateClient(TDFCredsPtr credsPtr, const char *kasUrl) {
    try {
        auto *creds = static_cast<virtru::OIDCCredentials *>(credsPtr);
        return new virtru::TDFClient(*creds, kasUrl);
    } catch (std::exception &e) {
        LogError(e.what());
    } catch (...) {
        LogDefaultError();
    }
    return nullptr;
}

/// Destruct the TDFClient instance.
DLL_PUBLIC void TDFDestroyClient(TDFClientPtr clientPtr) {
    try {
        auto *client = static_cast<virtru::TDFClient *>(clientPtr);
        delete client;
    } catch (std::exception &e) {
        LogError(e.what());
    } catch (...) {
        LogDefaultError();
    }
}

DLL_PUBLIC TDF_STATUS TDFAddDataAttribute(TDFClientPtr clientPtr,
                                          const char *dataAttribute,
                                          const char *kasUrl) {
    if (clientPtr == nullptr) {
        return TDF_STATUS_INVALID_PARAMS;
    }

    try {
        auto *client = static_cast<virtru::TDFClientBase *>(clientPtr);
        client->addDataAttribute(dataAttribute, kasUrl);
        return TDF_STATUS_SUCCESS;
    } catch (std::exception &e) {
        LogError(e.what());
    } catch (...) {
        LogDefaultError();
    }
    return TDF_STATUS_FAILURE;
}

/// Enable the internal logger class to write logs to the console for given LogLevel.
/// The default logLevel is 'Warn'
DLL_PUBLIC TDF_STATUS TDFEnableConsoleLogging(TDFClientPtr clientPtr, TDFLogLevel logLevel) {
    if (clientPtr == nullptr) {
        return TDF_STATUS_INVALID_PARAMS;
    }

    try {
        //TDFClient is a subclass of TDFClientBase, and `enableConsoleLogging`
        //is defined in TDFClientBase, so we have to cast to TDFClientBase
        //because C is not C++ and it ain't know nothin 'bout no classes.
        auto *client = static_cast<virtru::TDFClientBase *>(clientPtr);
        switch (logLevel) {
        case TDFLogLevelTrace:
            client->enableConsoleLogging(virtru::LogLevel::Trace);
            break;
        case TDFLogLevelDebug:
            client->enableConsoleLogging(virtru::LogLevel::Debug);
            break;
        case TDFLogLevelInfo:
            client->enableConsoleLogging(virtru::LogLevel::Info);
            break;
        case TDFLogLevelWarn:
            client->enableConsoleLogging(virtru::LogLevel::Warn);
            break;
        case TDFLogLevelError:
            client->enableConsoleLogging(virtru::LogLevel::Error);
            break;
        case TDFLogLevelFatal:
            client->enableConsoleLogging(virtru::LogLevel::Fatal);
            break;
        default:
            //dangit ya dummy, use a valid enum
            return TDF_STATUS_INVALID_PARAMS;
        }

        return TDF_STATUS_SUCCESS;
    } catch (std::exception &e) {
        LogError(e.what());
    } catch (...) {
        LogDefaultError();
    }
    return TDF_STATUS_FAILURE;
}

DLL_PUBLIC TDF_STATUS TDFEncryptFile(TDFClientPtr clientPtr, TDFStorageTypePtr data, const char *outFilepath) {
    if (clientPtr == nullptr || data == nullptr || outFilepath == nullptr) {
        return TDF_STATUS_INVALID_PARAMS;
    }

    try {
        auto *client = static_cast<virtru::TDFClient *>(clientPtr);
        virtru::TDFStorageType *storage = static_cast<virtru::TDFStorageType *>(data);
        client->encryptFile(*storage, outFilepath);
        return TDF_STATUS_SUCCESS;
    } catch (std::exception &e) {
        LogError(e.what());
    } catch (...) {
        LogDefaultError();
    }
    return TDF_STATUS_FAILURE;
}

/// Decrypt the contents of the TDF file into its original content.
DLL_PUBLIC TDF_STATUS TDFDecryptFile(TDFClientPtr clientPtr, TDFStorageTypePtr storageTypePtr, const char *outFilepath) {
    if (clientPtr == nullptr || storageTypePtr == nullptr || outFilepath == nullptr) {
        return TDF_STATUS_INVALID_PARAMS;
    }

    try {
        auto *client = static_cast<virtru::TDFClient *>(clientPtr);
        auto *storage = static_cast<virtru::TDFStorageType *>(storageTypePtr);
        client->decryptFile(*storage, outFilepath);

        return TDF_STATUS_SUCCESS;
    } catch (std::exception &e) {
        LogError(e.what());
    } catch (...) {
        LogDefaultError();
    }
    return TDF_STATUS_FAILURE;
}

DLL_PUBLIC TDF_STATUS TDFEncryptString(TDFClientPtr clientPtr,
                                       TDFStorageTypePtr storageTypePtr,
                                       TDFBytesPtr *outBytesPtr,
                                       TDFBytesLength *outBytesLength) {
    if (clientPtr == nullptr) {
        LogError("Invalid inBytes pointer!");
        return TDF_STATUS_INVALID_PARAMS;
    }
    if (storageTypePtr == nullptr) {
        LogError("Invalid tdf storage type ointer!");
        return TDF_STATUS_INVALID_PARAMS;
    }
    if (outBytesPtr == nullptr) {
        LogError("Invalid outBytes pointer!");
        return TDF_STATUS_INVALID_PARAMS;
    }
    if (outBytesLength == nullptr) {
        LogError("Invalid outBytesLen pointer!");
        return TDF_STATUS_INVALID_PARAMS;
    }

    try {
        auto *client = static_cast<virtru::TDFClient *>(clientPtr);
        auto *storage = static_cast<virtru::TDFStorageType *>(storageTypePtr);
        auto tdfData = client->encryptData(*storage);

        // Copy the encrypted payload.
        *outBytesLength = tdfData.size();
        *outBytesPtr = static_cast<unsigned char *>(malloc(*outBytesLength));
        std::copy(tdfData.begin(), tdfData.end(),
                  *outBytesPtr);

        return TDF_STATUS_SUCCESS;
    } catch (std::exception &e) {
        LogError(e.what());
    } catch (...) {
        LogDefaultError();
    }
    return TDF_STATUS_FAILURE;
}

/// Decrypt the TDF data
DLL_PUBLIC TDF_STATUS TDFDecryptString(TDFClientPtr clientPtr,
                                       TDFStorageTypePtr storageTypePtr,
                                       TDFBytesPtr *outBytesPtr,
                                       TDFBytesLength *outBytesLength) {
    if (clientPtr == nullptr ||
            storageTypePtr == nullptr ||
        outBytesPtr == nullptr ||
        outBytesLength == nullptr) {
        return TDF_STATUS_INVALID_PARAMS;
    }

    try {
        auto *client = static_cast<virtru::TDFClient *>(clientPtr);
        auto *storage = static_cast<virtru::TDFStorageType *>(storageTypePtr);

        auto decryptedData = client->decryptData(*storage);

        *outBytesLength = decryptedData.size();
        // Copy the decrypted data to the out buffer.
        *outBytesPtr = static_cast<unsigned char *>(malloc(*outBytesLength));
        std::copy(decryptedData.begin(), decryptedData.end(),
                  *outBytesPtr);

        return TDF_STATUS_SUCCESS;
    } catch (std::exception &e) {
        LogError(e.what());
    } catch (...) {
        LogDefaultError();
    }
    return TDF_STATUS_FAILURE;
}

DLL_PUBLIC TDF_STATUS TDFDecryptDataPartial(TDFClientPtr clientPtr,
                                            TDFStorageTypePtr storageTypePtr,
                                            TDFBytesLength offset,
                                            TDFBytesLength length,
                                            TDFBytesPtr *outBytesPtr,
                                            TDFBytesLength *outBytesLength) {
    if (clientPtr == nullptr ||
        storageTypePtr == nullptr ||
        outBytesPtr == nullptr ||
        outBytesLength == nullptr) {
        return TDF_STATUS_INVALID_PARAMS;
    }

    if (length == 0) {
        return TDF_STATUS_SUCCESS;
    }

    try {
        auto *client = static_cast<virtru::TDFClient *>(clientPtr);
        virtru::TDFStorageType *storage = static_cast<virtru::TDFStorageType *>(storageTypePtr);

        auto decryptedData = client->decryptDataPartial(*storage, offset, length);

        *outBytesLength = decryptedData.size();
        // Copy the decrypted data to the out buffer.
        *outBytesPtr = static_cast<unsigned char *>(malloc(*outBytesLength));
        std::copy(decryptedData.begin(), decryptedData.end(),
                  *outBytesPtr);

        return TDF_STATUS_SUCCESS;
    } catch (std::exception &e) {
        LogError(e.what());
    } catch (...) {
        LogDefaultError();
    }
    return TDF_STATUS_FAILURE;
}

/// Gets the JSON policy (as string) of a string-encoded TDF payload
DLL_PUBLIC TDF_STATUS TDFGetPolicy(TDFClientPtr clientPtr,
                                   TDFStorageTypePtr storageTypePtr,
                                   TDFBytesPtr *outBytesPtr,
                                   TDFBytesLength *outBytesLength) {
    if (clientPtr == nullptr ||
        storageTypePtr == nullptr ||
        outBytesPtr == nullptr ||
        outBytesLength == nullptr) {
        return TDF_STATUS_INVALID_PARAMS;
    }

    try {
        auto *client = static_cast<virtru::TDFClient *>(clientPtr);
        auto *storage = static_cast<virtru::TDFStorageType *>(storageTypePtr);

        std::string policyStr = client->getPolicy(*storage);

        *outBytesLength = policyStr.length();
        // Copy the policy string data to the out buffer.
        *outBytesPtr = static_cast<unsigned char *>(malloc(*outBytesLength));
        std::copy(policyStr.begin(), policyStr.end(),
                  *outBytesPtr);

        return TDF_STATUS_SUCCESS;
    } catch (std::exception &e) {
        LogError(e.what());
    } catch (...) {
        LogDefaultError();
    }
    return TDF_STATUS_FAILURE;
}

/// Assign the metadata that will be encrypted and stored in
/// the TDF, separately from the data.
DLL_PUBLIC TDF_STATUS TDFSetEncryptedMetadata(TDFClientPtr clientPtr,
                                              TDFCBytesPtr inBytesPtr,
                                              TDFBytesLength inBytesLength) {

    LogTrace("TDFSetEncryptedMetadata");

    if (clientPtr == nullptr || inBytesPtr == nullptr) {
        return TDF_STATUS_INVALID_PARAMS;
    }

    try {
        auto *client = static_cast<virtru::TDFClient *>(clientPtr);

        client->setEncryptedMetadata({reinterpret_cast<char const *>(inBytesPtr),
                                      inBytesLength});

        return TDF_STATUS_SUCCESS;
    } catch (std::exception &e) {
        LogError(e.what());
    } catch (...) {
        LogDefaultError();
    }
    return TDF_STATUS_FAILURE;
}


/// Decrypt and return TDF metadata as a string. If the TDF content has
/// no encrypted metadata, will return an empty string.
DLL_PUBLIC TDF_STATUS TDFGetEncryptedMetadata(TDFClientPtr clientPtr,
                                              TDFStorageTypePtr storageTypePtr,
                                              TDFBytesPtr *outBytesPtr,
                                              TDFBytesLength *outBytesLength) {
    LogTrace("TDFGetEncryptedMetadata");

    if (clientPtr == nullptr ||
        storageTypePtr == nullptr ||
        outBytesPtr == nullptr ||
        outBytesLength == nullptr) {
        return TDF_STATUS_INVALID_PARAMS;
    }

    try {
        auto *client = static_cast<virtru::TDFClient *>(clientPtr);

        virtru::TDFStorageType *storage = static_cast<virtru::TDFStorageType *>(storageTypePtr);

        auto metadata = client->getEncryptedMetadata(*storage);

        *outBytesLength = metadata.length();
        *outBytesPtr = nullptr;

        // Copy the metadata string data to the out buffer.
        if (!metadata.empty()) {

            *outBytesPtr = static_cast<unsigned char *>(malloc(*outBytesLength));
            std::copy(metadata.begin(), metadata.end(),
                      *outBytesPtr);
        }

        return TDF_STATUS_SUCCESS;
    } catch (std::exception &e) {
        LogError(e.what());
    } catch (...) {
        LogDefaultError();
    }
    return TDF_STATUS_FAILURE;

}

#ifdef __cplusplus
}
#endif
