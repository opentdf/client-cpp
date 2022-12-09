/*
* Copyright 2021 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
// Created by Sujan Reddy on 12/2/22.
//

#ifndef TDF_CLIENT_OPENID_CONFIGURATION_H
#define TDF_CLIENT_OPENID_CONFIGURATION_H

#include <string>

// auth/realms/tdf/.well-known/openid-configuration


namespace virtru {
    class OpenIDConfiguration {
    public:
        // Constructor
        explicit OpenIDConfiguration(const std::string& openIdConfigUrl);

        // Destructor
        ~OpenIDConfiguration() = default;

    public:
        [[nodiscard]] std::string getOIDCUrl() const;

    private:
        std::string m_configuration;
        std::string m_openIdConfigUrl;
    };
}
#endif //TDF_CLIENT_OPENID_CONFIGURATION_H
