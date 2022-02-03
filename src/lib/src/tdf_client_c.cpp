/*
 * Copyright 2022 Virtru Corporation
 *
 * SPDX - License - Identifier: MIT
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

/// Destruct the credentials instance.
DLL_PUBLIC void TDFDestroyCredential(TDFCredsPtr creds) {
    auto *policy = static_cast<virtru::OIDCCredentials *>(creds);
    delete policy;
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

DLL_PUBLIC TDF_STATUS TDFEncryptFile(TDFClientPtr clientPtr, const char *inFilepath, const char *outFilepath) {
    if (clientPtr == nullptr || inFilepath == nullptr || outFilepath == nullptr) {
        return TDF_STATUS_INVALID_PARAMS;
    }

    try {
        auto *client = static_cast<virtru::TDFClient *>(clientPtr);
        client->encryptFile(inFilepath, outFilepath);
        return TDF_STATUS_SUCCESS;
    } catch (std::exception &e) {
        LogError(e.what());
    } catch (...) {
        LogDefaultError();
    }
    return TDF_STATUS_FAILURE;
}

/// Decrypt the contents of the TDF file into its original content.
DLL_PUBLIC TDF_STATUS TDFDecryptFile(TDFClientPtr clientPtr, const char *inFilepath, const char *outFilepath) {
    if (clientPtr == nullptr || inFilepath == nullptr || outFilepath == nullptr) {
        return TDF_STATUS_INVALID_PARAMS;
    }

    try {
        auto *client = static_cast<virtru::TDFClient *>(clientPtr);
        client->decryptFile(inFilepath, outFilepath);

        return TDF_STATUS_SUCCESS;
    } catch (std::exception &e) {
        LogError(e.what());
    } catch (...) {
        LogDefaultError();
    }
    return TDF_STATUS_FAILURE;
}

DLL_PUBLIC TDF_STATUS TDFEncryptString(TDFClientPtr clientPtr,
                                       TDFCBytesPtr inBytesPtr,
                                       TDFBytesLength inBytesLength,
                                       TDFBytesPtr *outBytesPtr,
                                       TDFBytesLength *outBytesLength) {
    if (clientPtr == nullptr ||
        inBytesPtr == nullptr ||
        outBytesPtr == nullptr ||
        outBytesLength == nullptr) {
        return TDF_STATUS_INVALID_PARAMS;
    }

    try {
        auto *client = static_cast<virtru::TDFClient *>(clientPtr);
        auto tdfData = client->encryptString({reinterpret_cast<char const *>(inBytesPtr), inBytesLength});

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
                                       TDFCBytesPtr inBytesPtr,
                                       TDFBytesLength inBytesLength,
                                       TDFBytesPtr *outBytesPtr,
                                       TDFBytesLength *outBytesLength) {
    if (clientPtr == nullptr ||
        inBytesPtr == nullptr ||
        outBytesPtr == nullptr ||
        outBytesLength == nullptr) {
        return TDF_STATUS_INVALID_PARAMS;
    }

    try {
        auto *client = static_cast<virtru::TDFClient *>(clientPtr);

        std::string decryptedData = client->decryptString({reinterpret_cast<char const *>(inBytesPtr), inBytesLength});

        *outBytesLength = decryptedData.length();
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

#ifdef __cplusplus
}
#endif
