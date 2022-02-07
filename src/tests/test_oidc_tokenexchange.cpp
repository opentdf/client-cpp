//
//  TDF SDK
//
//  Copyright 2022 Virtru Corporation
//

#define BOOST_TEST_MODULE test_oidc_tokenexchange

#include "logger.h"
#include "network/http_client_service.h"
#include "oidc_credentials.h"
#include "policy_object.h"
#include "sdk_constants.h"
#include "tdf.h"
#include "tdf_client.h"
#include "tdf_exception.h"
#include "tdf_logging_interface.h"
#include "tdfbuilder.h"

#include <boost/test/included/unit_test.hpp>
#include <iostream>

using namespace virtru;

#include "network_interface.h"

const auto externalExchangeToken = "myExtTokenString";
const auto clientSecret = "boo";

const auto caCert = "-----BEGIN CERTIFICATE-----\n"
                    "MIIB3zCCAYWgAwIBAgIUe0HfcaJ1+OfWfyQPSyLByoZGoCAwCgYIKoZIzj0EAwMw\n"
                    "RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu\n"
                    "dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMDA4MjEyMDA2MzhaFw0zMDA4MTky\n"
                    "MDA2MzhaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD\n"
                    "VQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjO\n"
                    "PQMBBwNCAARfJz2GrhzM7bsTKgUhEtwYU+VtbcpLQAbCZUwgDhFXSxr5QRCoC3YM\n"
                    "MRheaKnFgig0Ipp0ECalgc0GAjGdyuq6o1MwUTAdBgNVHQ4EFgQUTG7WlIftUDQL\n"
                    "6sPUpcGVMCY0mHYwHwYDVR0jBBgwFoAUTG7WlIftUDQL6sPUpcGVMCY0mHYwDwYD\n"
                    "VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNIADBFAiEApGll20UoQT6/PN/DiOas\n"
                    "mhvSyr4hOBSKbymD4SHEIwUCIEzDMMogmFSJh4W1WqtK6Tme/XEPtWd4nGigwBTK\n"
                    "k5vv\n"
                    "-----END CERTIFICATE-----\n"s;

const auto kasPubKey = "\"-----BEGIN CERTIFICATE-----\nMIIDsjCCApqgAwIBAgIUYmcYT3eh9l8K/zgMhY+N6+5BX8gwDQYJKoZIhvcNAQEM\nBQAwcDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkRDMRMwEQYDVQQHDApXYXNoaW5n\ndG9uMQ8wDQYDVQQKDAZWaXJ0cnUxDDAKBgNVBAMMA2thczEgMB4GCSqGSIb3DQEJ\nARYRZGV2b3BzQHZpcnRydS5jb20wIBcNMTkwMzIyMDQ1MTA2WhgPMzAxODA3MjMw\nNDUxMDZaMHAxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJEQzETMBEGA1UEBwwKV2Fz\naGluZ3RvbjEPMA0GA1UECgwGVmlydHJ1MQwwCgYDVQQDDANrYXMxIDAeBgkqhkiG\n9w0BCQEWEWRldm9wc0B2aXJ0cnUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\nMIIBCgKCAQEAp0gprQxQTjj6furvVQnK3m6u7YpEjZNl5ze66MUjaD7dMYislTyq\nBoqUeLQ0w7xhqoJYGobQfweWLmzIuuntwemAYtBgRt5a5nImJsYQCLA1YEOhXMBo\niVV6qC8be9bzus1j+EDpB+HCn0nQZXnc617Kob3o/Z1FNfoSum+r1h8Og86lsA5G\np3oIMRtYNZF57UI/K858Dyyo/7AI2AFtoUQLYUDS9nFtU6cdX4HuNYvwaxV4P0Mt\nirXyG5xd/T6/Uf1iGqy1Xd8jYOM/2Tbe9feZ/LeWQHvJaBOvZZrpt58xTu3QTBEA\nCqNNoAQ+jP4/h/aXYB2HBe1wB3MLXLvIYwIDAQABo0IwQDAdBgNVHQ4EFgQUBmyt\nQTHTdqx5KqP7ip12Xey+UWUwHwYDVR0jBBgwFoAUBmytQTHTdqx5KqP7ip12Xey+\nUWUwDQYJKoZIhvcNAQEMBQADggEBAHghOOSNq/so2GXAftnU43tDzmDxcegxE4Yf\nIBfOqepkMVSZiCSz4c66HxtuYQGDqvreWBcPj17HLS6XAbujIzVb8DM8EDQl1sB7\nc7DC5Uwg095nu7TLSsYdzNGw+1bMq7eOyNWDNDY3/kEekK2h1FhzUsWQZwPuLm8c\nJK/w/MkL+icoACuBxteueRvc7tugVCjE2J/xkvmBzvRuUqOYZgY0CdqNkO6lMZeV\nSczhTPJ8W5TO6LfSfvG1W62CjrQ7IjtE4dFr3Lz1HsnyhxmfxJ4oKH7E31lYgmj/\niYWvx/RskN/+Byt19t84htwM0zr1uinCb1NF+xkOsha22AKJ9Rc=\n-----END CERTIFICATE-----\n\"";

using HttpHeaders = std::unordered_map<std::string, std::string>;

// callback once the http request is completed.
using HTTPServiceCallback = std::function<void(unsigned int statusCode, std::string &&response)>;

class MockNetwork : public INetwork {

  public: //INetwork members
    static std::unique_ptr<virtru::network::Service> Create(const std::string &url,
                                                            std::string_view sdkConsumerCertAuthority,
                                                            const std::string &clientKeyFileName,
                                                            const std::string &clientCertFileName) {
        BOOST_TEST_MESSAGE("Mock service constructed");
        LogTrace("Mock Service::Create");
    };

    virtual void executeGet(const std::string &url, const HttpHeaders &headers, HTTPServiceCallback &&callback, const std::string &ca, const std::string &key, const std::string &cert) override {
        LogTrace("Mock Service::Get");
        callback(200, kasPubKey);
    }

    virtual void executePost(const std::string &url, const HttpHeaders &headers, std::string &&body, HTTPServiceCallback &&callback, const std::string &ca, const std::string &key, const std::string &cert) override {
        LogTrace("Mock Service::Post");

        if (body.find("urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange") != std::string::npos) {
            BOOST_TEST_MESSAGE("executePost token exchange test Passed");
        } else {
            LogDebug("executePost token exchange test failed - Body: " + body);
            BOOST_FAIL("executePost token exchange test Failed");
        }

        if (body.find(externalExchangeToken) != std::string::npos) {
            BOOST_TEST_MESSAGE("executePost token exchange test Passed");
        } else {
            BOOST_FAIL("executePost token exchange test Failed");
        }

        const auto OIDCAccessToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJGRjJKM0o5TjNGQWQ0dnpLVDd2aEloZE1DTEVudE1PejVtLWhGNm5ScFNZIn0.eyJleHAiOjE2MTQxMTgzNzgsImlhdCI6MTYxNDExODA3OCwianRpIjoiNWQ4OTczYjYtYjg5Yy00OTBjLWIzYTYtMTM0ZDMxOTYxZTM3IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL2V4YW1wbGUtcmVhbG0iLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiN2ZkZGJkYWQtNDlmYS00NWU4LTg4MzItMzI3ZGI4ZjU1MDE1IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiZXhhbXBsZS1yZWFsbS1jbGllbnQiLCJzZXNzaW9uX3N0YXRlIjoiOTA0MTc4NTAtNWEwNC00ZmU1LTgxZWMtOTkzZDY1MmVhYmY5IiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIiwic3VwaXJpIjoidG9rZW5fc3VwaXJpIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJjbGFpbSI6eyJuYW1lIjp7InVzZXJuYW1lIjoiZm9vIn19LCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJqZWZmNS1leGFtcGxlIn0.NfM272HpLfyHACNJrXniyPF5klXjfB8QbhHBt_aTlZUF1-wO7W4-3qL02bMYe71dg_swR5WLFR0SL-zqa9zeKfsegL8E-lEeRSCcFwTvoSXPXSZ06tafFmSNxuA88MogG_3ZBhi9sUL5uAXtCoC3Rkb6xpb-JdHp42n68s_Mm1teCU2wx2rS6O1k23YCK3lY_xRsmV62sQ_tx973N5u7YHPxWsKVi-gHNlW3N0x23bRsEk-qcIq-3ug5cLOyADlNUeApTmug9lXGJxqxo3jlugnuf6VUtMwI1x8xSbePwC1pmGAfzZX2pS0kEUiGSHdH7flzibrMG70IXlutmS3e8Q";

        LogDebug("Returning 200");
        callback(200, "{\"" + std::string(kAccessToken) + "\" : \"" + OIDCAccessToken + "\", \"" + std::string(kRefreshToken) + "\" : \"bbbbb\"}");
        LogDebug("Returned 200");
    }

    virtual void executePatch(const std::string &url, const HttpHeaders &headers, std::string &&body, HTTPServiceCallback &&callback, const std::string &ca, const std::string &key, const std::string &cert) override {
        LogTrace("Mock Service::Patch");
        BOOST_FAIL("No PATCH expected");
        callback(0, "");
    }
};

constexpr auto OIDC_ENDPOINT = "xhttps://localhost:8443";
constexpr auto KAS_URL = "xhttp://localhost:8080/kas";

BOOST_AUTO_TEST_SUITE(test_oidc_tokenexchange)

BOOST_AUTO_TEST_CASE(test_tokenexchange) {

    BOOST_TEST_MESSAGE("test_tokenexchange begin");

    Logger::getInstance().setLogLevel(virtru::LogLevel::Trace);
    Logger::getInstance().enableConsoleLogging();

    try {
        OIDCCredentials clientCreds;
        std::string clientID = "tdf-client";
        std::string organizationName = "organizationName";
        std::string oidcEndpoint = OIDC_ENDPOINT;

        LogTrace("Creating client credentials");
        clientCreds.setClientCredentialsTokenExchange(clientID,
                                                      clientSecret,
                                                      externalExchangeToken,
                                                      organizationName,
                                                      oidcEndpoint);

        LogTrace("Creating TDFClient");
        auto oidcClientTDF = std::make_unique<TDFClient>(clientCreds, KAS_URL);

        LogTrace("Creating mock network");
        std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>();

        LogTrace("setting mock network");
        oidcClientTDF->setHTTPServiceProvider(mockNetwork);

        LogTrace("encryptString");
        oidcClientTDF->encryptString("This is a test");

        BOOST_TEST_MESSAGE("TDF tokenexchange test passed.");
    } catch (const Exception &exception) {
        BOOST_FAIL(exception.what());
    } catch (const std::exception &exception) {
        BOOST_FAIL(exception.what());
        std::cout << exception.what() << std::endl;
    } catch (...) {
        BOOST_FAIL("Unknown exception...");
        std::cout << "Unknown..." << std::endl;
    }
}

BOOST_AUTO_TEST_SUITE_END()
