/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/22
//

#ifndef VIRTRU_JSON_CONSTANTS_H
#define VIRTRU_JSON_CONSTANTS_H

namespace virtru {

    /// Attribute Objects - Constants
    static constexpr auto kKeyAccessType            = "type";
    static constexpr auto kKeyAccessRemote          = "remote";
    static constexpr auto kKeyAccessRemoteWrapped   = "remoteWrapped";
    static constexpr auto kKeyAccessWrapped         = "wrapped";
    static constexpr auto kUrl                      = "url";
    static constexpr auto kProtocol                 = "protocol";
    static constexpr auto kKasProtocol              = "kas";
    static constexpr auto kWrappedKey               = "wrappedKey";
    static constexpr auto kPolicyBinding            = "policyBinding";
    static constexpr auto kEncryptedMetadata        = "encryptedMetadata";
    static constexpr auto kClientPublicKey          = "clientPublicKey";


    /// Entity Object - Constants
    static constexpr auto kUserId                   = "userId";
    static constexpr auto kAliases                  = "aliases";
    static constexpr auto kAttributes               = "attributes";
    static constexpr auto kJWt                      = "jwt";
    static constexpr auto kPublicKey                = "publicKey";
    static constexpr auto kSignerPublicKey          = "signerPublicKey";
    static constexpr auto kCert                     = "cert";
    static constexpr auto kAlgorithm                = "algorithm";
    static constexpr auto kECDefaultAlgorithm       = "ec:secp256r1";

    // Attribute object
    static constexpr auto kAttribute                = "attribute";
    static constexpr auto kSubjectAttributes        = "subject_attributes";
    static constexpr auto kTDFClaims                = "tdf_claims";
    static constexpr auto kPreferredUsername        = "preferred_username";

    /// Policy Object - Constants
    static constexpr auto kUid                      = "uuid";
    static constexpr auto kBody                     = "body";
    static constexpr auto kDataAttributes           = "dataAttributes";
    static constexpr auto kDissem                   = "dissem";

    /// Manifest - Constants
    static constexpr auto kCiphertext               = "ciphertext";
    static constexpr auto kIV                       = "iv";
    static constexpr auto kKeyAccess                = "keyAccess";
    static constexpr auto kIsStreamable             = "isStreamable";
    static constexpr auto kCipherAlgorithm          = "algorithm";
    static constexpr auto kRootSignatureAlg         = "alg";
    static constexpr auto kRootSignatureSig         = "sig";
    static constexpr auto kEncryptKeyType           = "type";
    static constexpr auto kSplitKeyType             = "split";
    
    static constexpr auto kMethod                   = "method";
    static constexpr auto kRootSignature            = "rootSignature";
    static constexpr auto kSegmentSizeDefault       = "segmentSizeDefault";
    static constexpr auto kEncryptedSegSizeDefault  = "encryptedSegmentSizeDefault";
    static constexpr auto kSegmentHashAlg           = "segmentHashAlg";
    static constexpr auto kSegments                 = "segments";
    static constexpr auto kPolicy                   = "policy";
    static constexpr auto kEntity                   = "entity";
    static constexpr auto kClientPayloadSignature   = "clientPayloadSignature";
    static constexpr auto kAuthToken                = "authToken";
    static constexpr auto kOIDCToken                = "idpJWT";
    static constexpr auto kNanoTDFHeader            = "header";

    static constexpr auto kIntegrityInformation     = "integrityInformation";
    static constexpr auto kEncryptionInformation    = "encryptionInformation";
    static constexpr auto kHash                     = "hash";
    static constexpr auto kSegmentSize              = "segmentSize";
    static constexpr auto kEncryptedSegmentSize     = "encryptedSegmentSize";

    static constexpr auto kCipherAlgorithmGCM       = "AES-256-GCM";
    static constexpr auto kCipherAlgorithmCBC       = "AES-256-CBC";

    static constexpr auto kRootSignatureAlgDefault  = "HS256";
    static constexpr auto kHmacIntegrityAlgorithm   = "HS256";
    static constexpr auto kGmacIntegrityAlgorithm   = "GMAC";

    static constexpr auto kAesBlockSize             = 16;
    static constexpr auto kGcmIvSize                = 12;
    static constexpr auto kCbcIvSize                = 16;
    static constexpr auto kNanoTDFIvSize           = 3;
    static constexpr auto kNanoTDFGMACLength       = 8;

    static constexpr auto kTDF2ManifestFileName     = "manifest.xml";
    static constexpr auto kTDF2PayloadFileName      = "0.payload";

    static constexpr auto kTDFManifestFileName     = "0.manifest.json";
    static constexpr auto kTDFPayloadFileName      = "0.payload";

    static constexpr auto kPayload                  = "payload";
    static constexpr auto kPayloadReferenceType     = "type";
    static constexpr auto kPayloadReference         = "reference";
    static constexpr auto kPayloadIsEncrypted       = "isEncrypted";
    static constexpr auto kPayloadZipProtcol        = "zip";
    static constexpr auto kPayloadHtmlProtcol       = "html";
    static constexpr auto kPayloadMimeType          = "mimeType";
    static constexpr auto kDefaultMimeType          = "application/octet-stream";
    static constexpr auto kEntityWrappedKey         = "entityWrappedKey";
    static constexpr auto kSessionPublicKey         = "sessionPublicKey";
    static constexpr auto kCurveName                = "curveName";

    static constexpr auto kAuthTokenType            = "JWT";
    static constexpr auto kRequestBody              = "requestBody"; //JWT field - request body
    static constexpr auto kSignedRequestToken       = "signedRequestToken";

    static constexpr auto kUpsert                   = "/upsert";
    static constexpr auto kUpsertV2                 = "/v2/upsert";
    static constexpr auto kRewrap                   = "/rewrap";
    static constexpr auto kRewrapV2                 = "/v2/rewrap";
    static constexpr auto kKasPubKeyPath            = "/kas_public_key";

    static constexpr auto kHTTPBadRequest           = 400;
    static constexpr auto kHTTPOk                   = 200;
    static constexpr auto kHTTPOkPartial            = 206;

    /// From: https://www.iana.org/assignments/message-headers/message-headers.xhtml
    /// HTTP Headers
    static constexpr auto kUserAgentKey            = "User-Agent";
    static constexpr auto kContentTypeKey          = "Content-Type";
    static constexpr auto kContentTypeJsonValue    = "application/json";
    static constexpr auto kHostKey                 = "Host";
    static constexpr auto kDateKey                 = "Date";
    static constexpr auto kAuthorizationKey        = "Authorization";
    static constexpr auto kSignedHeadersKey        = "X-Auth-SignedHeaders";
    static constexpr auto kSignedHeadersValue      = "content-type;date;host";
    static constexpr auto kSignedHeadersValueGet   = "date;host";
    static constexpr auto kAcceptKey               = "Accept";
    static constexpr auto kAcceptKeyValue          = "application/json; charset=utf-8";
    static constexpr auto kVirtruClientKey         = "X-Virtru-Client";
    static constexpr auto kVirtruPublicKey         = "X-Virtru-Public-Key";
    static constexpr auto kUserAgentValuePostFix   = "Virtru TDF C++ SDK";
    static constexpr auto kVirtruClientValue       = "virtru-cpp-sdk:0.0.0";
    static constexpr auto kVirtruNTDFHeaderKey     = "virtru-ntdf-version";
    static constexpr auto kRangeRequest            = "Range";
    static constexpr auto kContentTypeOctetStream  = "application/octet-stream";

    /// HTTP Verbs
    static constexpr auto kHttpGet                 = "GET";
    static constexpr auto kHttpPut                 = "PUT";
    static constexpr auto kHttpPost                = "POST";
    static constexpr auto kHttpPatch               = "PATCH";
    static constexpr auto kHttpHead                = "HEAD";

    /// HTML template attributes
    static constexpr auto kHTMLValueAttribute      = "value";
    static constexpr auto kHTMLIdAttribute         = "id";
    static constexpr auto kHTMLDataInput           = "data-input";
    static constexpr auto kHTMLDataManifest        = "data-manifest";

    // Log messages.
    static constexpr auto kEmptyPolicyMsg          = "This policy has an empty attributes list and an empty "
                                                     "dissemination list. This will allow any entity with a "
                                                     "valid Entity Object to access this TDF.";

    // XML TDF elements
    static constexpr auto kTrustedDataObjectElement = "TrustedDataObject";
    static constexpr auto kEncryptionInformationElement = "EncryptionInformation";
    static constexpr auto kBase64BinaryPayloadElement = "Base64BinaryPayload";
    static constexpr auto kMediaTypeAttribute = "mediaType";
    static constexpr auto kFilenameAttribute = "filename";
    static constexpr auto kIsEncryptedAttribute = "isEncrypted";
    static constexpr auto kTextPlainMediaType = "text/plain";
    static constexpr auto kAttributeValueAsTrue = "true";

    // OIDC constants
    static constexpr auto kBearerToken = "Bearer";
    static constexpr auto kClientCredentials = "client_credentials";
    static constexpr auto kPasswordCredentials = "password";
    static constexpr auto kClientID = "client_id";
    static constexpr auto kClientSecret = "client_secret";
    static constexpr auto kUsername = "username";
    static constexpr auto kPassword = "password";
    static constexpr auto kRefreshToken = "refresh_token";
    static constexpr auto kAccessToken = "access_token";
    static constexpr auto kTokenEndpoint = "token_endpoint";
    static constexpr auto kSubjectToken = "subject_token";
    static constexpr auto kTokenRequestAccess = "urn:ietf:params:oauth:token-type:access_token";
    static constexpr auto kExchangeToken = "urn:ietf:params:oauth:grant-type:token-exchange";
    static constexpr auto kTokenRequestType = "requested_token_type";
    static constexpr auto kGrantType = "grant_type";
    static constexpr auto kKCRealmPath = "/auth/realms/";
    static constexpr auto kOIDCTokenPath = "/protocol/openid-connect/token";
    static constexpr auto kOIDCUserinfoPath = "/protocol/openid-connect/userinfo";
    static constexpr auto kKeycloakPubkeyHeader = "X-VirtruPubKey";
    static constexpr auto kContentTypeUrlFormEncode = "application/x-www-form-urlencoded";

    // RCA
    static constexpr auto kRCACreate = "/create";
    static constexpr auto kRCALinks = "/links";
    static constexpr auto kRCAFinish = "/finish";
    static constexpr auto kUploadId = "uploadId";
    static constexpr auto kGeneratedKey = "generatedKey";
    static constexpr auto kPartNumber = "partNumber";
    static constexpr auto kRCALinkServiceKey = "key";
    static constexpr auto kRCAEtag = "ETag";

}  // namespace virtru

#endif //VIRTRU_JSON_CONSTANTS_H
