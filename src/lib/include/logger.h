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

#ifndef VIRTRU_LOGGER_H
#define VIRTRU_LOGGER_H

#define ENABLE_BOOST_LOG_FRAMEWORK 0

#include <cstring>
#include <iomanip>
#include <memory>
#include <chrono>

#include "tdf_logging_interface.h"

#if ENABLE_BOOST_LOG_FRAMEWORK
#include "boost/log/trivial.hpp"
#include "boost/log/utility/setup.hpp"
#endif

namespace virtru {

    // TODO: Need to comeback and fix the link issue on linux
    // NOTE: Running into some link issue on Linux so we are disabling

    /// TODO: Need to test on windows.
    #define __SOURCE_FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

    /// macro for logging
    #define LogTrace(message)    virtru::Logger::_LogTrace(message, __SOURCE_FILENAME__, __LINE__)
    #define LogDebug(message)    virtru::Logger::_LogDebug(message, __SOURCE_FILENAME__, __LINE__)
    #define LogInfo(message)     virtru::Logger::_LogInfo(message, __SOURCE_FILENAME__, __LINE__)
    #define LogWarn(message)     virtru::Logger::_LogWarning(message, __SOURCE_FILENAME__, __LINE__)
    #define LogError(message)    virtru::Logger::_LogError(message, __SOURCE_FILENAME__, __LINE__)
    #define LogFatal(message)    virtru::Logger::_LogFatal(message, __SOURCE_FILENAME__, __LINE__)

    #define IsLogLevelTrace()    virtru::Logger::_IsLogLevel(virtru::LogLevel::Trace)
    #define IsLogLevelDebug()    virtru::Logger::_IsLogLevel(virtru::LogLevel::Debug)
    #define IsLogLevelInfo()     virtru::Logger::_IsLogLevel(virtru::LogLevel::Info)
    #define IsLogLevelWarn()     virtru::Logger::_IsLogLevel(virtru::LogLevel::Warn)
    #define IsLogLevelError()    virtru::Logger::_IsLogLevel(virtru::LogLevel::Error)
    #define IsLogLevelFatal()    virtru::Logger::_IsLogLevel(virtru::LogLevel::Fatal)


    /// Utility method to write timestamp in ISO8601 format to output stream
    /// \return std::ostream reference.
    inline std::ostream& logCurrentISO8601TimeUTC(std::ostream& ostream) {
        using namespace std::chrono;

        auto now = system_clock::now();
        auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
        auto in_time_t = system_clock::to_time_t(now);

        ostream << std::put_time(gmtime(&in_time_t), "%FT%T");
        ostream << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';

        return ostream;
    }

    /// A simple logger class(singleton) providing abstraction over BOOST logging framework.
    class Logger {
    public: // Interface

        /// Returns the singleton instance of Logger, if the instance is not yet created it will create one.
        /// All the logs will be written to console by default.
        /// \return - Returns single instance of the Logger.
        static Logger& getInstance();

        /// Set the logger log level.
        /// \param logLevel - The log level.
        void setLogLevel(LogLevel logLevel);

#if ENABLE_BOOST_LOG_FRAMEWORK
        /// Enable the logger to write logs to the file.
        /// The logs are written to file 'virtru-tdf-sdk%N.log' in the current working directory.
        void enableFileLogging();

        /// Disable the logger to write logs to the file.
        void disableFileLogging();
#endif

        /// Enable the logger to write logs to the console.
        void enableConsoleLogging();

        /// Disable the logger to write logs to the console.
        void disableConsoleLogging();

        /// Set the external logger.
        /// NOTE: once this is set, the console and file logger will be disabled entirely.
        /// \param externalLogger - The external logger weak ptr.
        void setExternalLogger(std::shared_ptr<ILogger> externalLogger);

        /// Delete copy and move constructors and assign operators
        Logger(Logger const&) = delete;
        Logger(Logger&&) = delete;
        Logger& operator=(Logger const&) = delete;
        Logger& operator=(Logger &&) = delete;

        /// Log the messages if the trace severity levels is enabled for this logger.
        /// \param traceMessage - The trace message.
        /// \param fileName - The source file name.
        /// \param lineNumber - The current line number in the source file.
        static void _LogTrace(const std::string& traceMessage, const char* fileName, unsigned int lineNumber);

        /// Log the messages if the debug severity levels is enabled for this logger.
        /// \param debugMessage - The debug message.
        /// \param fileName - The source file name.
        /// \param lineNumber - The current line number in the source file.
        static void _LogDebug(const std::string& debugMessage, const char* fileName, unsigned int lineNumber);

        /// Log the messages if the info severity levels is enabled for this logger.
        /// \param infoMessage - The info message.
        /// \param fileName - The source file name.
        /// \param lineNumber - The current line number in the source file.
        static void _LogInfo(const std::string& infoMessage, const char* fileName, unsigned int lineNumber);

        /// Log the messages if the warning severity levels is enabled for this logger.
        /// \param warningMessage - The warning message.
        /// \param fileName - The source file name.
        /// \param lineNumber - The current line number in the source file.
        static void _LogWarning(const std::string& warningMessage, const char* fileName, unsigned int lineNumber);

        /// Log the messages if the error severity levels is enabled for this logger.
        /// \param erroMessage - The error message.
        /// \param fileName - The source file name.
        /// \param lineNumber - The current line number in the source file.
        static void _LogError(const std::string& errorMessage, const char* fileName, unsigned int lineNumber);

        /// Log the messages if the fatal severity levels is enabled for this logger.
        /// \param fatalMessage - The fatal message.
        /// \param fileName - The source file name.
        /// \param lineNumber - The current line number in the source file.
        static void _LogFatal(const std::string& fatalMessage, const char* fileName, unsigned int lineNumber);

        /// Checks to see if the specified log level is active.
        /// \param logLevel 
        /// \return - returns TRUE if logging is being emitted for the specified level
        static bool _IsLogLevel(LogLevel logLevel);

    protected:

        /// Constructor
        Logger();

        /// Destructor
        ~Logger();

    private: // Data
        std::shared_ptr<ILogger> m_callback;
        LogLevel m_logLevel;

#if ENABLE_BOOST_LOG_FRAMEWORK
        typedef boost::log::sinks::synchronous_sink< boost::log::sinks::text_file_backend > logfileSink;
        typedef boost::log::sinks::synchronous_sink< boost::log::sinks::text_ostream_backend > consoleSink;
        boost::shared_ptr<logfileSink> m_logfileSink;
        boost::shared_ptr<consoleSink> m_consoleSink;
#else
        bool m_enableConsoleLog;
#endif
    };

}  // namespace virtru

#endif //VIRTRU_LOGGER_H
