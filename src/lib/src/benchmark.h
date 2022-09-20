/*
* Copyright 2022 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
// Created by Sujan Reddy on 9/14/22.
//


#ifndef VIRTRU_BENCHMARK_H
#define VIRTRU_BENCHMARK_H

#include <string>
#include <chrono>

#include "logger.h"

namespace virtru {

    class Benchmark {
    public:
        /// Constructor
        /// \param logMessage
        Benchmark(const std::string& logMessage)
        : m_logMessage(logMessage) {
            if (Logger::_IsBenchmarkLogEnabled()) {
                m_startTime = std::chrono::high_resolution_clock::now();
            }
        }

        /// Destructor
        ~Benchmark() {
            if (Logger::_IsBenchmarkLogEnabled()) {
                auto endTime = std::chrono::high_resolution_clock::now();
                auto start = std::chrono::time_point_cast<std::chrono::microseconds>(m_startTime).time_since_epoch().count();
                auto end = std::chrono::time_point_cast<std::chrono::microseconds>(endTime).time_since_epoch().count();

                auto duration = end - start;
                double ms = duration * 0.001;

                std::ostringstream os;
                os << m_logMessage << ":" << ms << " ms";
                LogBenchmark(os.str());
            }
        }

    private:
        std::string m_logMessage;
        std::chrono::time_point<std::chrono::high_resolution_clock> m_startTime;
    };


}
#endif //VIRTRU_BENCHMARK_H
