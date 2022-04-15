/*
 * Copyright 2021 Virtru Corporation
 *
 * SPDX - License Identifier: BSD-3-Clause-Clear
 *
 */
//
//  TDF SDK
//

#include "nanotdf/ecc_mode.h"
#include "nanotdf_client.h"

#include "tdf_exception.h"
#include "test_utils.h"

#include <boost/endian/arithmetic.hpp>
#include <boost/filesystem.hpp>
#include <iostream>
#include <istream>

#ifdef _WINDOWS
#include <direct.h>
#define GetCurrentDir _getcwd
#else
#include <unistd.h>
#define GetCurrentDir getcwd
#endif

namespace virtru {
    /// Generate a random string.
    /// NOTE: Not really worried about the randomness of the string content.
    std::string TestUtils::randomString(std::size_t len) {
        std::string str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        std::string newstr;
        std::size_t pos;
        while(newstr.size() != len) {
            pos = ((rand() % (str.size() - 1)));
            newstr += str.substr(pos,1);
        }
        return newstr;
    }

    std::string TestUtils::getFileString(std::string fileName){
        std::ifstream inStream{fileName, std::ios_base::in | std::ios_base::binary};
        if (!inStream) {
            std::string errorMsg{"Failed to open file for reading:"};
            errorMsg.append(fileName);
            ThrowException(std::move(errorMsg));
        }

        // Get the stream size
        inStream.seekg(0, inStream.end);
        auto dataSize = inStream.tellg();
        inStream.seekg(0, inStream.beg);

        std::vector<char> result(dataSize);
        inStream.read(reinterpret_cast<char *>(result.data()), dataSize);

        std::string result_str(result.begin(), result.end());

        return result_str;
    }

    std::string TestUtils::getCurrentWorkingDir() {
        char buff[FILENAME_MAX];
        GetCurrentDir( buff, FILENAME_MAX );
        std::string current_working_dir(buff);
        return current_working_dir;
    }

    std::string TestUtils::replaceAll(std::string str, const std::string& from, const std::string& to) {
        std::size_t start_pos = 0;
        while((start_pos = str.find(from, start_pos)) != std::string::npos) {
            str.replace(start_pos, from.length(), to);
            start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
        }
        return str;
    }
}