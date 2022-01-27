/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License - Identifier: MIT
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/14.
//

#include "logger.h"

#include <chrono>
#include <stdio.h>

#if ENABLE_BOOST_LOG_FRAMEWORK
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/file.hpp>
#endif

#include <boost/log/utility/setup/common_attributes.hpp>

namespace virtru {

    using namespace std::chrono;
    static const std::string COMMON_FMT("[%TimeStamp%][%Severity%]%Message%");

    /// Returns the instance of Logger, if the instance is not yet create it will create one.
    Logger& Logger::getInstance() {
        static Logger logger; // thread-safe in c++ 11
        // Singleton instance of the logger.
        return logger;
    }

    /// Constructor
    Logger::Logger() {
#if ENABLE_BOOST_LOG_FRAMEWORK
        boost::log::register_simple_formatter_factory< boost::log::trivial::severity_level, char >("Severity");
        boost::log::add_common_attributes();
#else
        // Disable logging by default.
        m_enableConsoleLog = false;
#endif
        // Default to WARN level
        setLogLevel(LogLevel::Warn);
    }

    /// Destructor
    Logger::~Logger() {
#if ENABLE_BOOST_LOG_FRAMEWORK
        boost::log::core::get()->remove_all_sinks();
#endif
    }

    /// Set the logger log level.
    void Logger::setLogLevel(LogLevel logLevel) {
        // LogLevel::Current is a no-op placeholder, do not change level, ignore and return
        if (logLevel == LogLevel::Current)
            return;

        m_logLevel = logLevel;

#if ENABLE_BOOST_LOG_FRAMEWORK
        // Update the boost log level
        switch (m_logLevel) {
            case LogLevel::Trace:
                boost::log::core::get()->set_filter(
                        boost::log::trivial::severity >= boost::log::trivial::trace
                );
                break;

            case LogLevel::Debug:
                boost::log::core::get()->set_filter(
                        boost::log::trivial::severity >= boost::log::trivial::debug
                );
                break;

            case LogLevel::Info:
                boost::log::core::get()->set_filter(
                        boost::log::trivial::severity >= boost::log::trivial::info
                );
                break;

            case LogLevel::Warn:
                boost::log::core::get()->set_filter(
                        boost::log::trivial::severity >= boost::log::trivial::warning
                );
                break;

            case LogLevel::Error:
                boost::log::core::get()->set_filter(
                        boost::log::trivial::severity >= boost::log::trivial::error
                );
                break;

            case LogLevel::Fatal:
                boost::log::core::get()->set_filter(
                        boost::log::trivial::severity >= boost::log::trivial::fatal
                );
                break;
            default: // default to error:
                m_logLevel = LogLevel::Error;
                boost::log::core::get()->set_filter(
                        boost::log::trivial::severity >= boost::log::trivial::error
                );
                break;
        }
#endif
    }

#if ENABLE_BOOST_LOG_FRAMEWORK
    /// Enable the logger to write logs to the file.
    /// The logs are written to file 'virtru-tdf-sdk%N.log' in the current working directory.
    void Logger::enableFileLogging() {

        // Already set.
        if (m_logfileSink) {
            return;
        }

        // TODO: Need to the define/configure the location where to write the logs.
        // Output message to file, rotates when file reached 2mb or at midnight every day. Each log file
        // is capped at 2mb and total is 8mb
        m_logfileSink = boost::log::add_file_log (
                boost::log::keywords::file_name = "virtru-tdf-sdk%N.log",
                boost::log::keywords::rotation_size = 2 * 1024 * 1024, // 2MB
                boost::log::keywords::max_size = 8 * 1024 * 1024, // 8 MB - 4 files of 2MB
                boost::log::keywords::time_based_rotation = boost::log::sinks::file::rotation_at_time_point(0, 0, 0),
                boost::log::keywords::format = COMMON_FMT,
                boost::log::keywords::auto_flush = true
        );
    }

    /// Disable the logger to write logs to the file.
    void Logger::disableFileLogging() {

        // Never set
        if(!m_logfileSink) {
            return;
        }

        boost::log::core::get()->remove_sink(m_logfileSink);
        m_logfileSink.reset();
    }
#endif

    /// Enable the logger to write logs to the console.
    void Logger::enableConsoleLogging() {

#if ENABLE_BOOST_LOG_FRAMEWORK
        // Already set.
        if (m_consoleSink) {
            return;
        }

        m_consoleSink = boost::log::add_console_log(
                std::clog,
                boost::log::keywords::format = COMMON_FMT,
                boost::log::keywords::auto_flush = true
        );
        m_consoleSink->locked_backend()->auto_flush(true);
#else
        m_enableConsoleLog = true;
#endif

    }

    /// Disable the logger to write logs to the console.
    void Logger::disableConsoleLogging() {

#if ENABLE_BOOST_LOG_FRAMEWORK
        // Never set
        if(!m_consoleSink) {
            return;
        }

        boost::log::core::get()->remove_sink(m_consoleSink);
        m_consoleSink.reset();
#else
        m_enableConsoleLog = false;
#endif

    }

    /// Set the external logger.
    void Logger::setExternalLogger(std::shared_ptr<ILogger> externalLogger) {
        m_callback = std::move(externalLogger);
#if ENABLE_BOOST_LOG_FRAMEWORK
        boost::log::core::get()->remove_all_sinks();
#endif
    }

    /// Log the messages if the trace severity levels is enabled for this logger.
    void Logger::_LogTrace(const std::string& traceMessage, const char* fileName, unsigned int lineNumber) {

        if (Logger::getInstance().m_logLevel > LogLevel::Trace) {
            return;
        }

        if (auto sp = std::move(Logger::getInstance().m_callback)) {
            sp->TDFSDKLog({ LogLevel::Trace,
                            traceMessage,
                            fileName,
                            "",
                            lineNumber,
                            duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count()});

        } else {
#if ENABLE_BOOST_LOG_FRAMEWORK
            if (Logger::getInstance().m_logfileSink || Logger::getInstance().m_consoleSink) {
                BOOST_LOG_TRIVIAL(trace) << "[" << fileName << ":" << lineNumber << "]" << ":" << traceMessage;
            }
#else
            if (Logger::getInstance().m_enableConsoleLog) {
                logCurrentISO8601TimeUTC(std::clog) << " " << "[Trace]";

#ifndef VBUILD_BRANCH_PRODUCTION
                std::clog << "[" << fileName << ":" << lineNumber << "]";
#endif
                std::clog << traceMessage << "\n";
            }
#endif
        }
    }

    /// Log the messages if the debug severity levels is enabled for this logger.
    void Logger::_LogDebug(const std::string& debugMessage, const char* fileName, unsigned int lineNumber) {

        if (Logger::getInstance().m_logLevel > LogLevel::Debug) {
            return;
        }

        if (auto sp = std::move(Logger::getInstance().m_callback)) {
            sp->TDFSDKLog({ LogLevel::Debug,
                            debugMessage,
                            fileName,
                            "",
                            lineNumber,
                            duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count()});

        } else {

#if ENABLE_BOOST_LOG_FRAMEWORK
            if (Logger::getInstance().m_logfileSink || Logger::getInstance().m_consoleSink) {
                BOOST_LOG_TRIVIAL(debug) <<  "[" << fileName << ":" << lineNumber << "]" << ":" << debugMessage;
            }
#else
            if (Logger::getInstance().m_enableConsoleLog) {
                logCurrentISO8601TimeUTC(std::clog) << " " << "[Debug]";

#ifndef VBUILD_BRANCH_PRODUCTION
                std::clog << "[" << fileName << ":" << lineNumber << "]";
#endif
                std::clog << debugMessage << "\n";
            }
#endif
        }
    }

    /// Log the messages if the info severity levels is enabled for this logger.
    void Logger::_LogInfo(const std::string& infoMessage, const char* fileName, unsigned int lineNumber) {

        if (Logger::getInstance().m_logLevel > LogLevel::Info) {
            return;
        }

        if (auto sp = std::move(Logger::getInstance().m_callback)) {
            sp->TDFSDKLog({ LogLevel::Info,
                            infoMessage,
                            fileName,
                            "",
                            lineNumber,
                            duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count()});

        } else {
#if ENABLE_BOOST_LOG_FRAMEWORK
            if (Logger::getInstance().m_logfileSink || Logger::getInstance().m_consoleSink) {
                BOOST_LOG_TRIVIAL(info) << "[" << fileName << ":" << lineNumber << "]" << ":" << infoMessage;
            }
#else
            if (Logger::getInstance().m_enableConsoleLog) {
                logCurrentISO8601TimeUTC(std::clog) << " " << "[Info]";

#ifndef VBUILD_BRANCH_PRODUCTION
                std::clog << "[" << fileName << ":" << lineNumber << "]";
#endif
                std::clog << infoMessage << "\n";
            }
#endif
        }
    }

    /// Log the messages if the warning severity levels is enabled for this logger.
    void Logger::_LogWarning(const std::string& warningMessage, const char* fileName, unsigned int lineNumber) {

        if (Logger::getInstance().m_logLevel > LogLevel::Warn) {
            return;
        }

        if (auto sp = std::move(Logger::getInstance().m_callback)) {
            sp->TDFSDKLog({ LogLevel::Warn,
                            warningMessage,
                            fileName,
                            "",
                            lineNumber,
                            duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count()});

        } else {
#if ENABLE_BOOST_LOG_FRAMEWORK
            if (Logger::getInstance().m_logfileSink || Logger::getInstance().m_consoleSink) {
                BOOST_LOG_TRIVIAL(warning) << "[" << fileName << ":" << lineNumber << "]" << ":" << warningMessage;
            }
#else
            if (Logger::getInstance().m_enableConsoleLog) {
                logCurrentISO8601TimeUTC(std::clog) << " " << "[Warn]";

#ifndef VBUILD_BRANCH_PRODUCTION
                std::clog << "[" << fileName << ":" << lineNumber << "]";
#endif
                std::clog << warningMessage << "\n";
            }
#endif

        }
    }

    /// Log the messages if the error severity levels is enabled for this logger.
    void Logger::_LogError(const std::string& errorMessage, const char* fileName, unsigned int lineNumber) {

        if (Logger::getInstance().m_logLevel > LogLevel::Error) {
            return;
        }

        if (auto sp = std::move(Logger::getInstance().m_callback)) {
            sp->TDFSDKLog({ LogLevel::Error,
                            errorMessage,
                            fileName,
                            "",
                            lineNumber,
                            duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count()});

        } else {
#if ENABLE_BOOST_LOG_FRAMEWORK
            if (Logger::getInstance().m_logfileSink || Logger::getInstance().m_consoleSink) {
                BOOST_LOG_TRIVIAL(error) << "[" << fileName << ":" << lineNumber << "]" << ":" << errorMessage;
            }
#else
            if (Logger::getInstance().m_enableConsoleLog) {
                logCurrentISO8601TimeUTC(std::clog) << " " << "[Error]";

#ifndef VBUILD_BRANCH_PRODUCTION
                std::clog << "[" << fileName << ":" << lineNumber << "]";
#endif
                std::clog << errorMessage << "\n";
            }
#endif
        }
    }

    /// Log the messages if the fatal severity levels is enabled for this logger.
    void Logger::_LogFatal(const std::string& fatalMessage, const char* fileName, unsigned int lineNumber) {

        if (Logger::getInstance().m_logLevel > LogLevel::Fatal) {
            return;
        }

        if (auto sp = std::move(Logger::getInstance().m_callback)) {
            sp->TDFSDKLog({ LogLevel::Fatal,
                            fatalMessage,
                            fileName,
                            "",
                            lineNumber,
                            duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count()});

        } else {
#if ENABLE_BOOST_LOG_FRAMEWORK
            if (Logger::getInstance().m_logfileSink || Logger::getInstance().m_consoleSink) {
                BOOST_LOG_TRIVIAL(fatal) << "[" << fileName << ":" << lineNumber << "]" << ":" << fatalMessage;
            }
#else
            if (Logger::getInstance().m_enableConsoleLog) {
                logCurrentISO8601TimeUTC(std::clog) << " " << "[Fatal]";

#ifndef VBUILD_BRANCH_PRODUCTION
                std::clog << "[" << fileName << ":" << lineNumber << "]";
#endif
                std::clog << fatalMessage << "\n";
            }
#endif
        }
    }

    /// Check the log level.
    bool Logger::_IsLogLevel(LogLevel logLevel) {
        return Logger::getInstance().m_logLevel <= logLevel;
    }
}  // namespace virtru
