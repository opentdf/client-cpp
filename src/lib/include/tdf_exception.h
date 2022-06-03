/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/02.
//

#ifndef PROJECT_EXCEPTION_H
#define PROJECT_EXCEPTION_H

#include <stdexcept>
#include <string>
#include <sstream>
#include <map>
#include "tdf_error_codes.h"
#include "logger.h"

namespace virtru {

    using namespace std::string_literals;

    /// macro for exception
    #define EXPAND( x ) x
    #define GET_MACRO(_1,_2,NAME,...) NAME
    #define ThrowException(...) EXPAND(EXPAND(GET_MACRO(__VA_ARGS__, ThrowExceptionCode, ThrowExceptionNoCode))(__VA_ARGS__))
    #define ThrowExceptionNoCode(message)  virtru::_ThrowVirtruException(message, __SOURCE_FILENAME__, __LINE__)
    #define ThrowExceptionCode(message, code)  virtru::_ThrowVirtruException(message, __SOURCE_FILENAME__, __LINE__, code)


    class Exception : public std::runtime_error {
    public:
        explicit Exception(const std::string &what, int code = VIRTRU_GENERAL_ERROR) :
                std::runtime_error{"[Error code: "s + std::to_string(code) + "] " + what},
                m_code{code} {}

        int code() const noexcept {
            return m_code;
        }

    private:
        int m_code;
    };

    /// Utility method to throw exception with filename and line number.
    /// \param errorStringPrefix - The error message.
    /// \param fileName - The source file name.
    /// \param lineNumber - The current line number in the source file.
    /// \param code - The error code - default 1
    inline void _ThrowVirtruException(std::string &&errorStringPrefix, const char *fileName, unsigned int lineNumber, int code = VIRTRU_GENERAL_ERROR) {
        std::ostringstream os;
        os << " [" << fileName << ":" << lineNumber << "] ";

        //only log line number for DEBUG and TRACE
        if(IsLogLevelDebug() || IsLogLevelTrace()){
            throw Exception { os.str() + move (errorStringPrefix), code};
        }
        else{
            throw Exception { move (errorStringPrefix), code};
        }

         
    }
}  // namespace virtru

#endif //PROJECT_EXCEPTION_H


