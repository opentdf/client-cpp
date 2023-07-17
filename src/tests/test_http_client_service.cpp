//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/11.
//  Copyright 2019 Virtru Corporation
//

#define BOOST_TEST_MODULE test_http_client_service

#include "http_client_service.h"
#include "tdf_exception.h"
#include "utils.h"
#include "version.h"

#include <string>
#include <iostream>

#include "nlohmann/json.hpp"
#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(test_http_client_service_suite)

    using namespace virtru::network;

    BOOST_AUTO_TEST_CASE(test_http_client_service_get)
    {
        constexpr auto kasUrl = "https://www.virtru.com";
        constexpr auto AcceptHeaderKey = "Accept";
        constexpr auto AcceptHeaderValue = "application/json";
        constexpr auto UserAgentHeaderKey = "User-Agent";
        auto UserAgentValuePostFix = virtru::Utils::getUserAgentValuePostFix();

        auto service = Service::Create(kasUrl);
        service->AddHeader(AcceptHeaderKey, AcceptHeaderValue);

        // Set user agent (ex: <Mac OS/Linux>:Virtru TDF C++ SDK v0.1)
        std::ostringstream sdkUserAgent {BOOST_PLATFORM};
        sdkUserAgent << ":" << UserAgentValuePostFix;
        service->AddHeader(UserAgentHeaderKey, sdkUserAgent.str());

        IOContext ioContext;
        service->ExecuteGet(ioContext, [](ErrorCode errorCode, HttpResponse&& response) {
            if (errorCode && errorCode.value() != 1) { // something wrong.

                std::ostringstream os {"Error code: "};
                os << errorCode.value() << " " << errorCode.message();
                BOOST_FAIL(os.str());

                std::cerr << os.str() << std::endl;
                return;
            }

            BOOST_TEST_MESSAGE(response);

            std::string body = response.body().data();
            BOOST_REQUIRE(body.size() > 0);
            return;
        });

        // Run the context - It's blocking call until i/o operation is done.
        ioContext.run();
    }


    BOOST_AUTO_TEST_CASE(test_http_header_version_value)
    {
        std::string utilUserAgent = virtru::Utils::getUserAgentValuePostFix();

        BOOST_CHECK_EQUAL(utilUserAgent, "Openstack C++ SDK v" + std::to_string(opentdf_VERSION_MAJOR) + "." + std::to_string(opentdf_VERSION_MINOR));

        std::string utilClientValue = virtru::Utils::getClientValue();

        BOOST_CHECK_EQUAL(utilClientValue, std::string("openstack-cpp-sdk:") + opentdf_VERSION);
    }

BOOST_AUTO_TEST_SUITE_END()
