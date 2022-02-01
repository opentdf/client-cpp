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

/// Create a new Credential instance configured for PKI authentication.
/// \param credsPtr = Pointer to Credentials opaque object
/// \param oidcEndpoint - The OIDC server url
/// \param clientId - The client id
/// \param clientKeyFileName - The name of the file containing the client key
/// \param clientCertFileName - The name of the file containing the client certificate
/// \param certificateAuthority - The certificate authority to be used
/// \param organizationName - The OIDC realm or organization the client belongs to
DLL_PUBLIC TDF_STATUS TDFCreateCredentialPKI(TDFCredsPtr credsPtr,
                                              const char *oidcEndpoint,
                                              const char *clientId,
                                              const char *clientKeyFileName,
                                              const char *clientCertFileName,
                                              const char *sdkConsumerCertAuthority,
                                              const char *organizationName);

/// Create a new Credential instance configured for Client Credential authentication.
/// \param credsPtr = Pointer to Credentials opaque object
/// \param oidcEndpoint - The OIDC server url
/// \param clientId - The client id
/// \param clientSecret - The client secret
/// \param organizationName - The OIDC realm or organization the client belongs to
DLL_PUBLIC TDF_STATUS TDFCreateCredentialClientCreds(TDFCredsPtr credsPtr,
                                                      const char *oidcEndpoint,
                                                      const char *clientId,
                                                      const char *clientSecret,
                                                      const char *organizationName);

/// Create a new TDF client using provided credentials object
/// \param credsPtr - Creds object created by calling TDFCreateCredentialXXX
/// \param kasURL - URL of a key access service
/// NOTE: On failure returns NULL ptr.
DLL_PUBLIC TDFClientPtr TDFCreateClient(TDFCredsPtr credsPtr, const char *kasUrl);

/// Destruct the Virtru client instance.
/// \param vClientPtr - The pointer to Virtru client opaque object.
DLL_PUBLIC void TDFDestroyClient(TDFClientPtr vClientPtr);

/// Enable the internal logger class to write logs to the console for given LogLevel.
/// The default logLevel is 'Warn'
DLL_PUBLIC TDF_STATUS TDFEnableConsoleLogging(TDFClientPtr vClientPtr, TDFLogLevel logLevel);

/* /// Encrypt the contents of the input file into a TDF. In the process of encryption, a policy is */
/* /// associated with the TDF. The policy has a unique id which can be used to identify the TDF policy. */
/* /// \param vClientPtr - The pointer to Virtru client opaque object. */
/* /// \param vEncryptFileParamsPtr  - Encrypt file param opaque object holding all the required information for encrypt operations */
/* /// \param outPolicyId  - On success, it contains policy id. */
/* /// \return TDF_STATUS - VSTATUS_SUCCESS on success */
/* /// NOTE: The caller of the api should free outPolicyId buffer. */
/* DLL_PUBLIC TDF_STATUS VClientEncryptFile(VClientPtr vClientPtr, VEncryptFileParamsPtr vEncryptFileParamsPtr, char **outPolicyId); */

/* /// Decrypt the contents of the TDF file into its original content. */
/* /// \param vClientPtr - The pointer to Virtru client opaque object. */
/* /// \param inFilepath - The TDF file on which the decryption is performed */
/* /// \param outFilepath - The file path of the original content after successful decryption */
/* /// \return TDF_STATUS - VSTATUS_SUCCESS on success */
/* DLL_PUBLIC TDF_STATUS VClientDecryptFile(VClientPtr vClientPtr, const char *inFilepath, const char *outFilepath); */

/* /// Encrypt the plain data into a TDF. In the process of encryption, a policy is */
/* /// associated with the TDF. The policy has a unique id which can be used to identify the TDF policy. */
/* /// \param vClientPtr - The pointer to Virtru client opaque object. */
/* /// \param vEncryptStringParamsPtr  - Encrypt string param opaque object holding all the required information for encrypt operations */
/* /// \param outPolicyId  - On success, it contains policy id. */
/* /// \param outBytesPtr  - On success, it contains the encrypted tdf data. */
/* /// \param outBytesLength  - On success, it is length of the encrypted tdf data. */
/* /// \return TDF_STATUS - VSTATUS_SUCCESS on success */
/* /// NOTE: The caller of the api should free outPolicyId buffer and outBytesPtr. */
/* DLL_PUBLIC TDF_STATUS VClientEncryptString(VClientPtr vClientPtr, VEncryptStringParamsPtr vEncryptStringParamsPtr, */
/*                                            char **outPolicyId, VBytesPtr *outBytesPtr, VBytesLength *outBytesLength); */

/* /// Decrypt the TDF data */
/* /// \param vClientPtr - The pointer to Virtru client opaque object. */
/* /// \param inBytesPtr  - Pointer to buffer containing the TDF data. */
/* /// \param inBytesLength  - Length of buffer containing the TDF data. */
/* /// \param outBytesPtr  - On success, it contains the decrypted tdf data. */
/* /// \param outBytesLength  - On success, it is length of the decrypted tdf data. */
/* /// \return TDF_STATUS - VSTATUS_SUCCESS on success */
/* /// NOTE: The caller of the api should free outBytesPtr. */
/* DLL_PUBLIC TDF_STATUS VClientDecryptString(VClientPtr vClientPtr, VCBytesPtr inBytesPtr, */
/*                                            VBytesLength inBytesLength, VBytesPtr *outBytesPtr, VBytesLength *outBytesLength); */

/* /// Return the policy associated with the given policy uuid. */
/* /// \param vClientPtr - The pointer to Virtru client opaque object. */
/* /// \param policyUUID - The unique policy uuid. */
/* /// \param vPolicyPtr - On success, it hold the ptr to the policy object. */
/* /// \return TDF_STATUS - VSTATUS_SUCCESS on success */
/* /// NOTE: The caller of the api should free vPolicyPtr. */
/* DLL_PUBLIC TDF_STATUS VClientFetchPolicyForUUID(VClientPtr vClientPtr, const char *policyUUID, VPolicyPtr *vPolicyPtr); */

/* /// Set the KAS url that will be used for tdf3 operations. */
/* /// \param vClientPtr - The pointer to Virtru client opaque object. */
/* /// \param kasUrl - The base URL for KAS communication. */
/* /// \return TDF_STATUS - VSTATUS_SUCCESS on success */
/* DLL_PUBLIC TDF_STATUS VClientSetKasUrl(VClientPtr vClientPtr, const char *kasUrl); */

/* /// Set the OIDC IdP url that will be used to authenticate against. */
/* /// \param vClientPtr - The pointer to Virtru client opaque object. */
/* /// \param oidcUrl - The base URL for the OIDC IdP (e.g. Keycloak) for the client to authenticate against. */
/* /// \return TDF_STATUS - VSTATUS_SUCCESS on success */
/* DLL_PUBLIC TDF_STATUS VClientSetOIDCProviderUrl(VClientPtr vClientPtr, const char *oidcUrl); */

/* /// DEPRECATED OIDC auth flows do not use EAS. */
/* ///  Set the EAS url that will be used for tdf3 operations. */
/* /// \param vClientPtr - The pointer to Virtru client opaque object. */
/* /// \param easUrl - The base URL for EAS communication. */
/* /// \return TDF_STATUS - VSTATUS_SUCCESS on success */
/* DLL_PUBLIC TDF_STATUS VClientSetEasUrl(VClientPtr vClientPtr, const char *easUrl); */

/* /// Set the ACM url that will be used for TDF policy sync operations. */
/* /// \param vClientPtr - The pointer to Virtru client opaque object. */
/* /// \param acmUrl - The base URL for ACM communication. */
/* /// \return TDF_STATUS - VSTATUS_SUCCESS on success */
/* DLL_PUBLIC TDF_STATUS VClientSetAcmUrl(VClientPtr vClientPtr, const char *acmUrl); */

/* /// Set the secure reader url which will be used in html tdf. */
/* /// \param vClientPtr - The pointer to Virtru client opaque object. */
/* /// \param srUrl - The URL for Secure reader. */
/* /// \return TDF_STATUS - VSTATUS_SUCCESS on success */
/* DLL_PUBLIC TDF_STATUS VClientSetSecureReaderUrl(VClientPtr vClientPtr, const char *srUrl); */

#ifdef __cplusplus
}
#endif

#endif // TDF_CLIENT_C_H
