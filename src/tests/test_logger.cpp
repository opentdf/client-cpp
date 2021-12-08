//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/11.
//  Copyright 2019 Virtru Corporation
//

#define BOOST_TEST_MODULE test_logger_suit

#include "tdf_logging_interface.h"
#include "logger.h"
#include "tdf_exception.h"

#include <string>
#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>

#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(test_logger_suite)

    using namespace std::chrono;
    using namespace virtru;

    BOOST_AUTO_TEST_CASE(test_logger_interface)
    {
        class ExternalLogger : public ILogger {
        public:

            /// A callback interface for log messages.
            void TDFSDKLog(LogMessage logMessage) override {

                std::ostringstream os;
                std::time_t timeInSeconds = (logMessage.timestamp/1000);
                std::size_t fractionalSeconds = (logMessage.timestamp % 1000);
                os << "[" << std::put_time(std::localtime(&timeInSeconds), "%m-%d-%Y %X") << "." << fractionalSeconds << "]";
                std::string logTime = os.str();

                switch (logMessage.level) {
                    case LogLevel::Current:
                        // no-op here to avoid compiler warning about unhandled case for 'Current'
                        break;

                    case LogLevel::Trace:
                        std::clog << logTime << "[Trace] " << logMessage.message << std::endl;
                        BOOST_FAIL("Testing external logger - Failed(log level is Info)");
                        break;

                    case LogLevel::Debug:
                        std::clog << logTime << "[Debug] " << logMessage.message << std::endl;
                        BOOST_FAIL("Testing external logger - Failed(log level is Info)");
                        break;

                    case LogLevel::Info:
                        std::clog << logTime << "[Info] " << logMessage.message << std::endl;
                        BOOST_TEST(static_cast<int>(logMessage.level) == static_cast<int>(LogLevel::Info));
                        BOOST_TEST("Info log message" == logMessage.message);
                        break;

                    case LogLevel::Warn:
                        std::clog << logTime << "[Warn] " << logMessage.message << std::endl;
                        BOOST_TEST(static_cast<int>(logMessage.level) == static_cast<int>(LogLevel::Warn));
                        BOOST_TEST("Warn log message" == logMessage.message);
                        break;

                    case LogLevel::Error:
                        std::clog << logTime << "[Error] " << logMessage.message << std::endl;
                        BOOST_TEST(static_cast<int>(logMessage.level) == static_cast<int>(LogLevel::Error));
                        BOOST_TEST("Error log message" == logMessage.message);;
                        break;

                    case LogLevel::Fatal:
                        std::clog << logTime << "[Fatal] " << logMessage.message << std::endl;
                        BOOST_TEST(static_cast<int>(logMessage.level) == static_cast<int>(LogLevel::Fatal));
                        BOOST_TEST("Fatal log message" == logMessage.message);
                        break;
                }
            }
        };
        std::shared_ptr<ExternalLogger> externalLogger = std::make_shared<ExternalLogger>();

        Logger::getInstance().setLogLevel(virtru::LogLevel::Info);
        Logger::getInstance().setExternalLogger(externalLogger);

        LogTrace("Trace log message");
        LogDebug("Debug log message");
        LogInfo("Info log message");
        LogWarn("Warn log message");
        LogError("Error log message");
        LogFatal("Fatal log message");

        // This should remove the external logger since we hold shared_ptr of the
        // external logger interface.
        externalLogger.reset();

        Logger::getInstance().setLogLevel(virtru::LogLevel::Trace);

        Logger::getInstance().enableConsoleLogging();

#if ENABLE_BOOST_LOG_FRAMEWORK
        // TODO: validate these tests by parsing the log file.
        Logger::getInstance().enableFileLogging();

        // These logs should show in the log file and on console.
        LogTrace("Trace log message shown in file and console");
        LogDebug("Debug log message shown in file and console");
        LogError("Error log message shown in file and console");
        LogFatal("Fatal log message shown in file and console");

        Logger::getInstance().disableFileLogging();
#endif
        // These logs should show only in console.
        LogTrace("Trace log message show only in console");
        LogDebug("Debug log message show only in console");
        LogError("Error log message show only in console");
        LogFatal("Fatal log message show only in console");

        Logger::getInstance().disableConsoleLogging();

        // These logs should NOT shown any where.
        LogTrace("Trace log message should NOT shown any where");
        LogDebug("Debug log message should NOT shown any where");
        LogError("Error log message should NOT shown any where");
        LogFatal("Fatal log message should NOT shown any where");

        // Verify that IsLogLevel is working
        Logger::getInstance().setLogLevel(virtru::LogLevel::Info);

        // Debug is ***not*** active at the Info setting
        BOOST_TEST(!IsLogLevelDebug());

        // Info is active at the Info setting
        BOOST_TEST(IsLogLevelInfo());

        // Warn is active at the Info setting
        BOOST_TEST(IsLogLevelWarn());
    }

BOOST_AUTO_TEST_SUITE_END()
