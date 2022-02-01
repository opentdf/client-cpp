/*
 * Copyright 2022 Virtru Corporation
 *
 * SPDX - License - Identifier: MIT
 *
 */

#include <logger.h>
#include <tdf_constants.h>
#include <tdf_client.h>
#include <tdf_client_c.h>
#include <policy_object.h>

#include <algorithm>
#include <sstream>

#ifdef __cplusplus
extern "C" {
#endif

/// Hack to allow .NET P/Invoke to free native memory for a random pointer
/// \param vMemoryPtr - The malloc'd memory to be freed.
DLL_PUBLIC TDF_STATUS TDFFreeMemory(void *vMemoryPtr) {
    if (vMemoryPtr == nullptr) {
        return TDF_STATUS_INVALID_PARAMS;
    }

    try {
        free(vMemoryPtr);
        return TDF_STATUS_SUCCESS;
    } catch (std::exception &e) {
        LogError(e.what());
    } catch (...) {
        LogDefaultError();
    }
    return TDF_STATUS_FAILURE;
}

DLL_PUBLIC TDF_STATUS TDFCreateCredentialPKI(
    TDFCredsPtr credsPtr, const char *oidcEndpoint, const char *clientId,
    const char *clientKeyFileName, const char *clientCertFileName,
    const char *sdkConsumerCertAuthority, const char *organizationName) {

    if (credsPtr == nullptr) {
        return TDF_STATUS_INVALID_PARAMS;
    }

    auto *creds = static_cast<virtru::OIDCCredentials *>(credsPtr);
    creds->setClientCredentialsPKI(clientId, clientKeyFileName,
                                   clientCertFileName, sdkConsumerCertAuthority,
                                   organizationName, oidcEndpoint);

    return TDF_STATUS_SUCCESS;
}

DLL_PUBLIC TDF_STATUS TDFCreateCredentialClientCreds(
    TDFCredsPtr credsPtr, const char *oidcEndpoint, const char *clientId,
    const char *clientSecret, const char *organizationName) {
    if (credsPtr == nullptr) {
        return TDF_STATUS_INVALID_PARAMS;
    }

    auto *creds = static_cast<virtru::OIDCCredentials *>(credsPtr);
    creds->setClientCredentialsClientSecret(clientId, clientSecret,
                                            organizationName, oidcEndpoint);

    return TDF_STATUS_SUCCESS;
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

// // Encrypt the contents of the input file into a TDF. In the process of
// encryption, a policy is
// /// associated with the TDF. The policy has a unique id which can be used to
// identify the TDF policy. DLL_PUBLIC VSTATUS VClientEncryptFile(VClientPtr
// vClientPtr, VEncryptFileParamsPtr vEncryptFileParamsPtr,
//                                       char** outPolicyId)
// {
// 	if (vClientPtr == nullptr || vEncryptFileParamsPtr == nullptr) {
// 		return VSTATUS_INVALID_PARAMS;
// 	}

// 	try {
// 		auto* client = static_cast<virtru::Client*>(vClientPtr);
// 		auto* fileParams =
// static_cast<virtru::EncryptFileParams*>(vEncryptFileParamsPtr);

// 		std::string policyId = client->encryptFile(*fileParams);

// 		// Copy the policyId to the outPolicyId buffer.
// 		*outPolicyId = static_cast<char*>(malloc(policyId.size() + 1));
// 		std::copy(policyId.begin(), policyId.end(), *outPolicyId);
// 		(*outPolicyId)[policyId.size()] = '\0';

// 		return VSTATUS_SUCCESS;
// 	}
// 	catch (std::exception& e) {
// 		LogError(e.what());
// 	}
// 	catch (...) {
// 		LogDefaultError();
// 	}
// 	return VSTATUS_FAILURE;
// }

// /// Decrypt the contents of the TDF file into its original content.
// DLL_PUBLIC VSTATUS VClientDecryptFile(VClientPtr vClientPtr, const char*
// inFilepath, const char* outFilepath)
// {
// 	if (vClientPtr == nullptr || inFilepath == nullptr || outFilepath ==
// nullptr) { 		return VSTATUS_INVALID_PARAMS;
// 	}

// 	try {
// 		auto* client = static_cast<virtru::Client*>(vClientPtr);
// 		client->decryptFile(inFilepath, outFilepath);

// 		return VSTATUS_SUCCESS;
// 	}
// 	catch (std::exception& e) {
// 		LogError(e.what());
// 	}
// 	catch (...) {
// 		LogDefaultError();
// 	}
// 	return VSTATUS_FAILURE;
// }

// /// Encrypt the plain data into a TDF. In the process of encryption, a policy
// is
// /// associated with the TDF. The policy has a unique id which can be used to
// identify the TDF policy. DLL_PUBLIC VSTATUS VClientEncryptString(VClientPtr
// vClientPtr, VEncryptStringParamsPtr vEncryptStringParamsPtr,
//                                         char** outPolicyId, VBytesPtr*
//                                         outBytesPtr, VBytesLength*
//                                         outBytesLength)
// {
// 	if (vClientPtr == nullptr || vEncryptStringParamsPtr == nullptr
// 		|| outPolicyId == nullptr || outBytesPtr == nullptr
// 		|| outBytesLength == nullptr) {
// 		return VSTATUS_INVALID_PARAMS;
// 	}

// 	try {
// 		auto* client = static_cast<virtru::Client*>(vClientPtr);
// 		auto* stringParams =
// static_cast<virtru::EncryptStringParams*>(vEncryptStringParamsPtr);

// 		auto [policyId, tdfData] = client->encryptString(*stringParams);

// 		// Copy the policyId to the outPolicyId buffer.
// 		*outPolicyId = static_cast<char*>(malloc(policyId.size() + 1));
// 		std::copy(policyId.begin(), policyId.end(), *outPolicyId);
// 		(*outPolicyId)[policyId.size()] = '\0';

// 		// Copy the encrypted payload.
// 		*outBytesLength = tdfData.size();
// 		*outBytesPtr = static_cast<unsigned
// char*>(malloc(*outBytesLength)); 		std::copy(tdfData.begin(), tdfData.end(),
// *outBytesPtr);

// 		return VSTATUS_SUCCESS;
// 	}
// 	catch (std::exception& e) {
// 		LogError(e.what());
// 	}
// 	catch (...) {
// 		LogDefaultError();
// 	}
// 	return VSTATUS_FAILURE;
// }

// /// Decrypt the TDF data
// DLL_PUBLIC VSTATUS VClientDecryptString(VClientPtr vClientPtr, VCBytesPtr
// inBytesPtr,
//                                         VBytesLength inBytesLength,
//                                         VBytesPtr* outBytesPtr, VBytesLength*
//                                         outBytesLength)
// {
// 	if (vClientPtr == nullptr || inBytesPtr == nullptr || outBytesPtr ==
// nullptr || outBytesLength == nullptr) { 		return VSTATUS_INVALID_PARAMS;
// 	}

// 	try {
// 		auto* client = static_cast<virtru::Client*>(vClientPtr);

// 		std::stringstream decryptDataStream;
// 		std::stringstream tdfStream;
// 		tdfStream.write((char*)inBytesPtr, inBytesLength);

// 		client->decryptStream(tdfStream, decryptDataStream);

// 		// Get the stream size.
// 		decryptDataStream.seekg(0, std::ios::end);
// 		*outBytesLength = decryptDataStream.tellg();
// 		decryptDataStream.seekg(0, std::ios::beg);

// 		// Copy the decrypted data to the out buffer.
// 		*outBytesPtr = static_cast<unsigned
// char*>(malloc(*outBytesLength)); 		decryptDataStream.read((char*)*outBytesPtr,
// *outBytesLength);

// 		return VSTATUS_SUCCESS;
// 	}
// 	catch (std::exception& e) {
// 		LogError(e.what());
// 	}
// 	catch (...) {
// 		LogDefaultError();
// 	}
// 	return VSTATUS_FAILURE;
// }

// /// Return the policy associated with the given policy uuid.
// DLL_PUBLIC VSTATUS VClientFetchPolicyForUUID(VClientPtr vClientPtr, const
// char* policyUUID, VPolicyPtr* vPolicyPtr)
// {
// 	if (vClientPtr == nullptr || policyUUID == nullptr) {
// 		return VSTATUS_INVALID_PARAMS;
// 	}

// 	try {
// 		auto* client = static_cast<virtru::Client*>(vClientPtr);

// 		auto policy = client->fetchPolicyForUUID(policyUUID);
// 		*vPolicyPtr = VPolicyCreate();

// 		// Copy the contents using assignment.
// 		auto* newPolicy = static_cast<virtru::Policy*>(*vPolicyPtr);
// 		*newPolicy = policy;

// 		return VSTATUS_SUCCESS;
// 	}
// 	catch (std::exception& e) {
// 		LogError(e.what());
// 	}
// 	catch (...) {
// 		LogDefaultError();
// 	}
// 	return VSTATUS_FAILURE;
// }

// DLL_PUBLIC VSTATUS VClientSetKasUrl(VClientPtr vClientPtr, const char*
// kasUrl)
// {
// 	if (vClientPtr == nullptr || kasUrl == nullptr) {
// 		return VSTATUS_INVALID_PARAMS;
// 	}

// 	try {
// 		auto* client = static_cast<virtru::Client*>(vClientPtr);

// 		client->setKasUrl(kasUrl);

// 		return VSTATUS_SUCCESS;
// 	}
// 	catch (std::exception& e) {
// 		LogError(e.what());
// 	}
// 	catch (...) {
// 		LogDefaultError();
// 	}
// 	return VSTATUS_FAILURE;
// }

// DLL_PUBLIC VSTATUS VClientSetOIDCProviderUrl(VClientPtr vClientPtr, const
// char* oidcUrl)
// {
// 	if (vClientPtr == nullptr || oidcUrl == nullptr) {
// 		return VSTATUS_INVALID_PARAMS;
// 	}

// 	try {
// 		auto* client = static_cast<virtru::Client*>(vClientPtr);

// 		client->setOIDCProviderUrl(oidcUrl);

// 		return VSTATUS_SUCCESS;
// 	}
// 	catch (const std::exception& e) {
// 		LogError(e.what());
// 	}
// 	catch (...) {
// 		LogDefaultError();
// 	}
// 	return VSTATUS_FAILURE;
// }

// DLL_PUBLIC VSTATUS VClientSetEasUrl(VClientPtr vClientPtr, const char*
// easUrl)
// {
// 	if (vClientPtr == nullptr || easUrl == nullptr) {
// 		return VSTATUS_INVALID_PARAMS;
// 	}
// 	try {
// 		auto* client = static_cast<virtru::Client*>(vClientPtr);

// 		client->setEasUrl(easUrl);

// 		return VSTATUS_SUCCESS;
// 	}
// 	catch (std::exception& e) {
// 		LogError(e.what());
// 	}
// 	catch (...) {
// 		LogDefaultError();
// 	}
// 	return VSTATUS_FAILURE;
// }

// DLL_PUBLIC VSTATUS VClientSetAcmUrl(VClientPtr vClientPtr, const char*
// acmUrl)
// {
// 	if (vClientPtr == nullptr || acmUrl == nullptr) {
// 		return VSTATUS_INVALID_PARAMS;
// 	}
// 	try {
// 		auto* client = static_cast<virtru::Client*>(vClientPtr);

// 		client->setAcmUrl(acmUrl);

// 		return VSTATUS_SUCCESS;
// 	}
// 	catch (std::exception& e) {
// 		LogError(e.what());
// 	}
// 	catch (...) {
// 		LogDefaultError();
// 	}
// 	return VSTATUS_FAILURE;
// }

// DLL_PUBLIC VSTATUS VClientSetSecureReaderUrl(VClientPtr vClientPtr, const
// char* srUrl)
// {
// 	if (vClientPtr == nullptr || srUrl == nullptr) {
// 		return VSTATUS_INVALID_PARAMS;
// 	}
// 	try {
// 		auto* client = static_cast<virtru::Client*>(vClientPtr);

// 		client->setSecureReaderURL(srUrl);

// 		return VSTATUS_SUCCESS;
// 	}
// 	catch (std::exception& e) {
// 		LogError(e.what());
// 	}
// 	catch (...) {
// 		LogDefaultError();
// 	}
// 	return VSTATUS_FAILURE;
// }

#ifdef __cplusplus
}
#endif
