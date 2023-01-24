/*
* Copyright 2021 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
// Created by Sujan Reddy on 12/2/22.
//

#ifndef TDF_CLIENT_OIDC_CONFIGURATION_H
#define TDF_CLIENT_OIDC_CONFIGURATION_H

#include <string>

// auth/realms/tdf/.well-known/openid-configuration


namespace virtru {
    class OIDCConfiguration {
    public:
        // Constructor
        explicit OIDCConfiguration(const std::string& oidcConfigUrl);

        // Destructor
        ~OIDCConfiguration() = default;

    public:
        [[nodiscard]] std::string getOIDCUrl() const;

    private:
        std::string m_configuration;
        std::string m_oidcConfigUrl;
    };
}
#endif //TDF_CLIENT_OIDC_CONFIGURATION_H
