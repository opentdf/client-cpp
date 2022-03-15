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

namespace virtru {

    using namespace std::string_literals;

    /// macro for open ssl exception
    #define ThrowException(message)  virtru::_ThrowVirtruException(message, __SOURCE_FILENAME__, __LINE__)

    class Exception : public std::runtime_error {
    public:
        explicit Exception(const std::string &what, int code = 1) :
                std::runtime_error{"Error code "s + std::to_string(code) + ". " + what},
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
    inline void _ThrowVirtruException(std::string &&errorStringPrefix, const char *fileName, unsigned int lineNumber) {
        std::ostringstream os;
        os << " [" << fileName << ":" << lineNumber << "] ";

        throw Exception { os.str() + move (errorStringPrefix)};
    }
}  // namespace virtru

#endif //PROJECT_EXCEPTION_H


