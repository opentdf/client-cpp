/*
 * Copyright 2021 Virtru Corporation
 *
 * SPDX - License Identifier: BSD-3-Clause-Clear
 *
 */
//
//  TDF SDK
//

#include <string>

#ifndef VIRTRU_TEST_UTILS_H
#define VIRTRU_TEST_UTILS_H

namespace virtru {
    class TestUtils {
        public:
            /// Get a random string of specified length
            /// \param len - length of string
            /// \return a random string
            static std::string randomString(std::size_t len);

            /// Return contents of file in string
            /// \param fileName - name of file
            /// \return string of contents of file
            static std::string getFileString(std::string fileName);

            /// Get current working directory
            /// \return current working directory
            static std::string getCurrentWorkingDir();

            /// Return contents of file in string
            /// \param str - string in which replacement is done
            /// \param from - what to replace
            /// \param to - what to replace with
            /// \return string after replacement
            static std::string replaceAll(std::string str, const std::string& from, const std::string& to);
    };
}

#endif // VIRTRU_TEST_UTILS_H