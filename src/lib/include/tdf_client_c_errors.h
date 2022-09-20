#ifndef TDF_CLIENT_C_ERRORS_H_
#define TDF_CLIENT_C_ERRORS_H_

#include "tdf_constants.h"
#include "tdf_constants_c.h"
#include "tdf_error_codes.h"
#include "tdf_exception.h"


/// Utility method to convert exceptions thrown by the C++ code into error codes
/// used by the C interop
inline TDF_STATUS convertVirtruExceptionToTDFStatus(const virtru::Exception e) {
    // TDFClient is a subclass of TDFClientBase, and `enableConsoleLogging`
    // is defined in TDFClientBase, so we have to cast to TDFClientBase
    // because C is not C++ and it ain't know nothin 'bout no classes.
    switch (e.code()) {
    case VIRTRU_GENERAL_ERROR:
        return TDF_STATUS_FAILURE;
    case VIRTRU_SYSTEM_ERROR:
        return TDF_STATUS_FAILURE_INTERNAL;
    case VIRTRU_NETWORK_ERROR:
        return TDF_STATUS_FAILURE_NETWORK;
    case VIRTRU_CRYPTO_ERROR:
        return TDF_STATUS_FAILURE_CRYPTO;
    case VIRTRU_TDF_FORMAT_ERROR:
        return TDF_STATUS_FAILURE_TDF_FORMAT;
    case VIRTRU_ATTR_OBJ_ERROR:
        return TDF_STATUS_FAILURE_ATTR_OBJ;
    case VIRTRU_POLICY_OBJ_ERROR:
        return TDF_STATUS_FAILURE_POLICY_OBJ;
    case VIRTRU_KAS_OBJ_ERROR:
        return TDF_STATUS_FAILURE_KAS_OBJ;
    case VIRTRU_NANO_TDF_FORMAT_ERROR:
        return TDF_STATUS_FAILURE_NANOTDF_FORMAT;
    default:
        // Just give up and return generic code
        return TDF_STATUS_FAILURE;
    }
}


#endif // TDF_CLIENT_C_ERRORS_H_
