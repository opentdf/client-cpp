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

#include "network_util.h"
#include "tdf_exception.h"

#include <ostream>


namespace virtru::network {

    /// Convert posix time to string format, based on locale.
    std::string toRfc1123(bpt::ptime time) {
        static const std::locale loc {
            std::locale::classic(), new bpt::time_facet{"%a, %d %b %Y %H:%M:%S GMT"}
        };

        std::ostringstream os;
        os.imbue(loc);
        os << time;
        return os.str();
    }

    /// Return the current timestamp based on the current locale.
    std::string nowRfc1123() {
        return toRfc1123 (bpt::second_clock::universal_time());
    }

    /// Utility method to throw boost network exception when there an error.
    void _ThrowBoostNetworkException(std::string&& errorString, int errorCode,
                                     const char* fileName, unsigned int lineNumber) {
        std::ostringstream os;
        os << " [" << fileName << ":" << lineNumber << "] ";
        throw Exception { os.str() + "Network - " + std::move(errorString), errorCode };
    }
}  // namespace virtru::network

