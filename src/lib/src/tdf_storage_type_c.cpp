/*
 * Copyright 2023 Virtru Corporation
 *
 * SPDX - License Identifier: BSD-3-Clause-Clear
 *
 */

#include "logger.h"
#include "tdf_storage_type.h"
#include "tdf_constants.h"

#ifdef __cplusplus
extern "C" {
#endif


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

DLL_PUBLIC TDF_STATUS TDFGetTDFStorageDescriptor(TDFStorageTypePtr storageTypePtr,
                                                        TDFBytesPtr *outBytesPtr,
                                                        TDFBytesLength *outBytesLength) {
    if (storageTypePtr == nullptr ||
        outBytesPtr == nullptr ||
        outBytesLength == nullptr) {
        return TDF_STATUS_INVALID_PARAMS;
    }

    try {
        auto *storage = static_cast<virtru::TDFStorageType *>(storageTypePtr);

        std::string descriptorStr = storage->getStorageDescriptor();

        *outBytesLength = descriptorStr.length();
        // Copy the string data to the out buffer.
        *outBytesPtr = static_cast<unsigned char *>(malloc(*outBytesLength));
        std::copy(descriptorStr.begin(), descriptorStr.end(),
                  *outBytesPtr);

        return TDF_STATUS_SUCCESS;
    } catch (virtru::Exception &e) {
        LogError(e.what());
        return convertVirtruExceptionToTDFStatus(e);
    } catch (std::exception &e) {
        LogError(e.what());
    } catch (...) {
        LogDefaultError();
    }
    return TDF_STATUS_FAILURE;
}

/// Destruct the storage instance.
DLL_PUBLIC void TDFDestroyStorage(TDFStorageTypePtr storage) {
    auto *storeCast = static_cast<virtru::TDFStorageType *>(storage);
    delete storeCast;
}

#ifdef __cplusplus
}
#endif
