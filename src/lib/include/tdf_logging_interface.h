/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/14.
//

#ifndef VIRTRU_LOGGING_INTERFACE_H
#define VIRTRU_LOGGING_INTERFACE_H

#include "tdf_constants.h"

#include <string>
#include <ctime>

namespace virtru {

    /// Log message data.
    struct LogMessage {
        LogLevel level;
        std::string message;
        std::string fileName;
        std::string function;
        unsigned int line;
        std::time_t timestamp; // time since epoch in milliseconds
    };

    /// An interface for log messages.
    ///
    /// If the consumer needs an access to the log message emitted by this library, they have to register an
    /// callback so they redirect to any output.
    ///
    class ILogger {
    public:
        virtual ~ILogger() = default;

        /// A callback interface for log messages.
        /// \param logMessage - The log message structure
        virtual void TDFSDKLog(LogMessage logMessage) = 0;
    };
}  // namespace virtru

#endif // VIRTRU_LOGGING_INTERFACE_H
