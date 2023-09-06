/*
* Copyright 2023 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/

#ifndef TDF_STORAGE_TYPE_C_H
#define TDF_STORAGE_TYPE_C_H

#include "tdf_constants_c.h"

#ifdef __cplusplus
extern "C" {
#endif

/// Destruct a credentials instance created with TDFCreateTDFStorageXXX
DLL_PUBLIC void TDFDestroyStorage(TDFStorageTypePtr storage);

/// Create a TDF Storage Type instance of type file
/// \param filePath - The path to the file
DLL_PUBLIC TDFStorageTypePtr TDFCreateTDFStorageFileType(const char *filePath);

/// Create a TDF Storage Type instance of type string
/// \param buffer - The buffer for the data
DLL_PUBLIC TDFStorageTypePtr TDFCreateTDFStorageStringType(TDFCBytesPtr inBytesPtr,
                                                           TDFBytesLength inBytesLength);

/// Create a TDF Storage Type instance of type S3
/// \param S3Url - https-prefixed URL to the object to be read
/// \param awsAccessKeyID - Access Key ID for the AWS credentials
/// \param awsSecretAccessKey - Secret access key for AWS credentials
/// \param awsRegionName - Region name for AWS credentials
DLL_PUBLIC TDFStorageTypePtr TDFCreateTDFStorageS3Type(const char *S3Url,
                                                       const char *awsAccessKeyId,
                                                       const char *awsSecretAccessKey,
                                                       const char *awsRegionName);

/// Returns the unique storage descriptor (path, bucket/key, etc) of the TDF pointed to
/// by a given TDFStorageType
/// \param tdfStorageTypePtr - Pointer to TDF storage type
/// \param outBytesPtr  - On success, it contains the descriptor string.
/// \param outBytesLength  - On success, it is length of the descriptor string.
DLL_PUBLIC TDF_STATUS TDFGetTDFStorageDescriptor(TDFStorageTypePtr storageTypePtr,
                                                        TDFBytesPtr *outBytesPtr,
                                                        TDFBytesLength *outBytesLength);

#ifdef __cplusplus
}
#endif

#endif // TDF_STORAGE_TYPE_C_H
