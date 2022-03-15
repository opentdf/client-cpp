/*
* Copyright 2022 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/

#ifndef TDF_CONSTANTS_C_H
#define TDF_CONSTANTS_C_H

#define LogDefaultError()    LogError("Default exception!");

#if defined _WIN32 || defined WIN32  || defined _WINDOWS || defined __CYGWIN__
  #ifdef _DLL
    #ifdef __GNUC__
      #define DLL_PUBLIC __attribute__ ((dllexport))
    #else
      #define DLL_PUBLIC __declspec(dllexport)
    #endif
  #else
    #ifdef __GNUC__
      #define DLL_PUBLIC __attribute__ ((dllimport))
    #else
      #define DLL_PUBLIC __declspec(dllimport)
    #endif
  #endif
  #define DLL_LOCAL
#else
  #if __GNUC__ >= 4
    #define DLL_PUBLIC __attribute__ ((visibility ("default")))
    #define DLL_LOCAL  __attribute__ ((visibility ("hidden")))
  #else
    #define DLL_PUBLIC
    #define DLL_LOCAL
  #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Status code
typedef enum {
    TDF_STATUS_SUCCESS = 0,
    TDF_STATUS_FAILURE = 1, // Generic failure
    TDF_STATUS_INVALID_PARAMS = 2 // Check the input parameters if they are valid.
} TDF_STATUS;

// TDF Protocol
typedef enum {
    TDFProtocolZip = 0,
    TDFProtocolHtml = 1
} TDFProtocol;

/// Defines a log level.
typedef enum  {
    TDFLogLevelTrace = 0,  /// Most detailed output
    TDFLogLevelDebug,
    TDFLogLevelInfo,
    TDFLogLevelWarn,
    TDFLogLevelError,
    TDFLogLevelFatal  /// Least detailed output
} TDFLogLevel;

// TDF client opaque object.
typedef void* TDFClientPtr;

// TDF creds opaque object.
typedef void* TDFCredsPtr;

// Policy opaque object.
typedef void* TDFPolicyPtr;

typedef unsigned char* TDFBytesPtr;
typedef const unsigned char* TDFCBytesPtr;
typedef unsigned int TDFBytesLength;

#ifdef __cplusplus
}
#endif

#endif //TDF_CONSTANTS_C_H
