/*
* Copyright 2022 Virtru Corporation
*
* SPDX - License - Identifier: MIT
*
*/

#ifndef TDF_CLIENT_C_H
#define TDF_CLIENT_C_H

#include "tdf_constants_c.h"

#ifdef __cplusplus
extern "C" {
#endif

/// Hack to allow .NET P/Invoke to free native memory for a random pointer
/// \param vMemoryPtr - The malloc'd memory to be freed.
DLL_PUBLIC TDF_STATUS TDFFreeMemory(void *memoryPtr);

/// Destruct a credentials instance created with TDFCreateCredentialXXX
DLL_PUBLIC void TDFDestroyCredential(TDFCredsPtr creds);

/// Create a new Credential instance configured for PKI authentication.
/// \param oidcEndpoint - The OIDC server url
/// \param clientId - The client id
/// \param clientKeyFileName - The name of the file containing the client key
/// \param clientCertFileName - The name of the file containing the client certificate
/// \param certificateAuthority - The certificate authority to be used
/// \param organizationName - The OIDC realm or organization the client belongs to
DLL_PUBLIC TDFCredsPtr TDFCreateCredentialPKI(const char *oidcEndpoint,
                                              const char *clientId,
                                              const char *clientKeyFileName,
                                              const char *clientCertFileName,
                                              const char *sdkConsumerCertAuthority,
                                              const char *organizationName);

/// Create a new Credential instance configured for Client Credential authentication.
/// \param oidcEndpoint - The OIDC server url
/// \param clientId - The client id
/// \param clientSecret - The client secret
/// \param organizationName - The OIDC realm or organization the client belongs to
DLL_PUBLIC TDFCredsPtr TDFCreateCredentialClientCreds(const char *oidcEndpoint,
                                                      const char *clientId,
                                                      const char *clientSecret,
                                                      const char *organizationName);

/// Create a new Credential instance configured for Client Credential authentication.
/// \param oidcEndpoint - The OIDC server url
/// \param clientId - The client id
/// \param clientSecret - The client secret
/// \param externalExchangeToken - An external token from the to be exchanged during auth via OIDC Token Exchange
/// \param organizationName - The OIDC realm or organization the client belongs to
DLL_PUBLIC TDFCredsPtr TDFCreateCredentialTokenExchange(const char *oidcEndpoint,
                                                        const char *clientId,
                                                        const char *clientSecret,
                                                        const char *externalExchangeToken,
                                                        const char *organizationName);

/// Create a new TDF client using provided credentials object
/// \param credsPtr - Creds object created by calling TDFCreateCredentialXXX
/// \param kasURL - URL of a key access service
/// NOTE: On failure returns NULL ptr.
DLL_PUBLIC TDFClientPtr TDFCreateClient(TDFCredsPtr credsPtr, const char *kasUrl);

/// Destruct the Virtru client instance.
/// \param clientPtr - The pointer to Virtru client opaque object.
DLL_PUBLIC void TDFDestroyClient(TDFClientPtr clientPtr);

/// Add a data attribute in URL format to the data being encrypted
/// \param dataAttribute - Attribute string in format: "https://example.com/attr/Classification/value/Alpha"
/// \param kasURL - URL of a key access service TODO currently ignored
DLL_PUBLIC TDF_STATUS TDFAddDataAttribute(TDFClientPtr clientPtr, const char *dataAttribute, const char *kasUrl);

/// Enable the internal logger class to write logs to the console for given LogLevel.
/// The default logLevel is 'Warn'
DLL_PUBLIC TDF_STATUS TDFEnableConsoleLogging(TDFClientPtr clientPtr, TDFLogLevel logLevel);

/// Encrypt the contents of the input file into a TDF. In the process of encryption, a policy is
/// associated with the TDF. The policy has a unique id which can be used to identify the TDF policy.
/// \param vClientPtr - The pointer to Virtru client opaque object.
/// \param vEncryptFileParamsPtr  - Encrypt file param opaque object holding all the required information for encrypt operations
/// \param outPolicyId  - On success, it contains policy id.
/// \return TDF_STATUS - VSTATUS_SUCCESS on success
/// NOTE: The caller of the api should free outPolicyId buffer.
DLL_PUBLIC TDF_STATUS TDFEncryptFile(TDFClientPtr clientPtr, const char *inFilepath, const char *outFilepath);

/// Decrypt the contents of the TDF file into its original content.
/// \param vClientPtr - The pointer to Virtru client opaque object.
/// \param inFilepath - The TDF file on which the decryption is performed
/// \param outFilepath - The file path of the original content after successful decryption
/// \return TDF_STATUS - VSTATUS_SUCCESS on success
DLL_PUBLIC TDF_STATUS TDFDecryptFile(TDFClientPtr clientPtr, const char *inFilepath, const char *outFilepath);

/// Encrypt the plain data into a TDF. In the process of encryption, a policy is
/// associated with the TDF. The policy has a unique id which can be used to identify the TDF policy.
/// \param vClientPtr - The pointer to Virtru client opaque object.
/// \param vEncryptStringParamsPtr  - Encrypt string param opaque object holding all the required information for encrypt operations
/// \param outPolicyId  - On success, it contains policy id.
/// \param outBytesPtr  - On success, it contains the encrypted tdf data.
/// \param outBytesLength  - On success, it is length of the encrypted tdf data.
/// \return TDF_STATUS - VSTATUS_SUCCESS on success
/// NOTE: The caller of the api should free outBytesPtr.
DLL_PUBLIC TDF_STATUS TDFEncryptString(TDFClientPtr clientPtr,
                                       TDFCBytesPtr inBytesPtr,
                                       TDFBytesLength inBytesLength,
                                       TDFBytesPtr *outBytesPtr,
                                       TDFBytesLength *outBytesLength);

/// Decrypt the TDF data
/// \param vClientPtr - The pointer to Virtru client opaque object.
/// \param inBytesPtr  - Pointer to buffer containing the TDF data.
/// \param inBytesLength  - Length of buffer containing the TDF data.
/// \param outBytesPtr  - On success, it contains the decrypted tdf data.
/// \param outBytesLength  - On success, it is length of the decrypted tdf data.
/// \return TDF_STATUS - VSTATUS_SUCCESS on success
/// NOTE: The caller of the api should free outBytesPtr.
DLL_PUBLIC TDF_STATUS TDFDecryptString(TDFClientPtr clientPtr,
                                       TDFCBytesPtr inBytesPtr,
                                       TDFBytesLength inBytesLength,
                                       TDFBytesPtr *outBytesPtr,
                                       TDFBytesLength *outBytesLength);

/// Gets the JSON policy (as string) of a string-encoded TDF payload
/// \param vClientPtr - The pointer to Virtru client opaque object.
/// \param inBytesPtr  - Pointer to buffer containing the TDF data.
/// \param inBytesLength  - Length of buffer containing the TDF data.
/// \param outBytesPtr  - On success, it contains the decrypted tdf data.
/// \param outBytesLength  - On success, it is length of the decrypted tdf data.
/// \return TDF_STATUS - VSTATUS_SUCCESS on success
/// NOTE: The caller of the api should free outBytesPtr.
DLL_PUBLIC TDF_STATUS TDFDecryptString(TDFClientPtr clientPtr,
                                       TDFCBytesPtr inBytesPtr,
                                       TDFBytesLength inBytesLength,
                                       TDFBytesPtr *outBytesPtr,
                                       TDFBytesLength *outBytesLength);

#ifdef __cplusplus
}
#endif

#endif // TDF_CLIENT_C_H
