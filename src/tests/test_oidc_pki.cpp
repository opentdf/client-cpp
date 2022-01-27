//
//  TDF SDK
//
//  Created by Pat Mancuso on 2022/01/14
//  Copyright 2022 Virtru Corporation
//

#define BOOST_TEST_MODULE test_oidc_pki

#include "logger.h"
#include "network/http_client_service.h"
#include "policy_object.h"
#include "sdk_constants.h"
#include "tdf.h"
#include "tdf_client.h"
#include "tdf_exception.h"
#include "tdf_logging_interface.h"
#include "tdfbuilder.h"
#include "oidc_credentials.h"

#include <boost/test/included/unit_test.hpp>
#include <iostream>
#include <stdio.h>

using namespace virtru;

#include "network_interface.h"

    const std::string clientKeyFileName = "clientkeyfile.dummy";
    const std::string clientCertFileName = "clientcertfile.dummy";
    const std::string certificateAuthorityFileName = "certificateAuthority.dummy";

    // $openssl req -new -x509 -key privatekey.pem -out publickey.cer -days 365
    // generates cert with public key.
    const auto publicKeyX509 = "-----BEGIN CERTIFICATE-----\n"
            "MIID1DCCArygAwIBAgIJAPco6TKljKMRMA0GCSqGSIb3DQEBCwUAMH8xCzAJBgNV\n"
            "BAYTAlVTMQswCQYDVQQIDAJOVjENMAsGA1UEBwwEUmVubzEPMA0GA1UECgwGVmly\n"
            "dHJ1MQwwCgYDVQQLDANFbmcxFDASBgNVBAMMC2V4YW1wbGUuY29tMR8wHQYJKoZI\n"
            "hvcNAQkBFhB1c2VyQGV4YW1wbGUuY29tMB4XDTE5MDQxNjEzNDkxNloXDTI0MDQx\n"
            "NDEzNDkxNlowfzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5WMQ0wCwYDVQQHDARS\n"
            "ZW5vMQ8wDQYDVQQKDAZWaXJ0cnUxDDAKBgNVBAsMA0VuZzEUMBIGA1UEAwwLZXhh\n"
            "bXBsZS5jb20xHzAdBgkqhkiG9w0BCQEWEHVzZXJAZXhhbXBsZS5jb20wggEiMA0G\n"
            "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrGSqlDXezSgcc+tWR/1LkJK3xk2JN\n"
            "eCxG3BcVI5Y7u3PrN8Cf9JEehrHBEbIDn1klMo/P/CG+jAVEd7+PgU9WDAxj59C6\n"
            "RAfAdMT4Emxvx2FffefUAbA0/I8lHrEQK2BPyggarjNSkeW3oPxqWqTZtHHj1AJH\n"
            "lv+3QZcTxol2Pnjirim0KT43JhxIHlYTdlGt0wzDPoAQlKRC2vV9yhDd/KLhsx3Q\n"
            "1UbW3iofZ9pidaIiYmyYIIEb2GZwvISF8CzfDvBjxMaTdbrCbrs1i3qRogyRh8r0\n"
            "xmk22qt5rZv59xf5t4s4E5gOX8UvkD8AtlPROMml/HA/PFL6EN429Sb/AgMBAAGj\n"
            "UzBRMB0GA1UdDgQWBBR99W23SPqQsdOp6jrXBgDkjaaKPDAfBgNVHSMEGDAWgBR9\n"
            "9W23SPqQsdOp6jrXBgDkjaaKPDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEB\n"
            "CwUAA4IBAQBcRXDE4TkMiCvLXO63fiF05x27fmg0ZUEbMQo/lkE4L0iU7EhN+v6+\n"
            "saUZc57OGL/JOGvNgol+6BMNAaRnvAub9pFbSY3KgkGbF7QRwisLQrZZ+JUOKPSf\n"
            "r3IMNpuMBlr6PN8b9EDxiyxwS0lxP4bbjWBnbOarVTrdL1/jV8OPkcNxAEHjYFac\n"
            "hAfuviZO82aaHBgJ13BkF+sxWF251PYu2dh3bGS6hUJi9BnD3d/fjMR5fpD98rj/\n"
            "dlX0BQhvkkCJUvXwZjpWwYYby29FMtSaw2fl9OPTrhceqmF4MfQO4hTAc/X91QOi\n"
            "nfNeYqBVj/7rB7QgK7Y6f4hpcq2QYr+g\n"
            "-----END CERTIFICATE-----\n"s;

    // openssl x509 -inform pem -in publickey.cer -pubkey -noout
    // Extract public key from cert
    const auto publicKeyPem = "-----BEGIN PUBLIC KEY-----\n"
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqxkqpQ13s0oHHPrVkf9S\n"
            "5CSt8ZNiTXgsRtwXFSOWO7tz6zfAn/SRHoaxwRGyA59ZJTKPz/whvowFRHe/j4FP\n"
            "VgwMY+fQukQHwHTE+BJsb8dhX33n1AGwNPyPJR6xECtgT8oIGq4zUpHlt6D8alqk\n"
            "2bRx49QCR5b/t0GXE8aJdj544q4ptCk+NyYcSB5WE3ZRrdMMwz6AEJSkQtr1fcoQ\n"
            "3fyi4bMd0NVG1t4qH2faYnWiImJsmCCBG9hmcLyEhfAs3w7wY8TGk3W6wm67NYt6\n"
            "kaIMkYfK9MZpNtqrea2b+fcX+beLOBOYDl/FL5A/ALZT0TjJpfxwPzxS+hDeNvUm\n"
            "/wIDAQAB\n"
            "-----END PUBLIC KEY-----\n";

    // $openssl genrsa -out privatekey.pem - generate a public key
    const auto privateKeyPem = "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEAqxkqpQ13s0oHHPrVkf9S5CSt8ZNiTXgsRtwXFSOWO7tz6zfA\n"
            "n/SRHoaxwRGyA59ZJTKPz/whvowFRHe/j4FPVgwMY+fQukQHwHTE+BJsb8dhX33n\n"
            "1AGwNPyPJR6xECtgT8oIGq4zUpHlt6D8alqk2bRx49QCR5b/t0GXE8aJdj544q4p\n"
            "tCk+NyYcSB5WE3ZRrdMMwz6AEJSkQtr1fcoQ3fyi4bMd0NVG1t4qH2faYnWiImJs\n"
            "mCCBG9hmcLyEhfAs3w7wY8TGk3W6wm67NYt6kaIMkYfK9MZpNtqrea2b+fcX+beL\n"
            "OBOYDl/FL5A/ALZT0TjJpfxwPzxS+hDeNvUm/wIDAQABAoIBACw3DLYqjMxgTQZI\n"
            "K/jWqm0arXjIRZcPfyGwrqZf0+sLviEC/1xWr0ncNQNXt1EIVNkv/8oXtgCv3oyb\n"
            "BX3oRMBPzMPknCQGgJpTkrMoz6zzMU6kEszOwuJuge9txwQOsYztALskWU71NRAH\n"
            "IjO5yPAZmXTuzMgDVYHeCVSq8csEXbg72FKG+XsyVZRETw+DEeBTdo5RRz++eHiF\n"
            "UVfNgLyky1yHHiAA9LeOceq5FoYumOAQXnjCdZ+4vW2i+pFvgPIRQcccC9fjDzRC\n"
            "ZtqYFnVgOgGVBiJb3VX/G7Cn+872TmwI6WOf/Me/OW3I0l7FCDizeCKbMvPVtHFr\n"
            "9CpZm4ECgYEA1Xa6y15XKkKL45X6Ds3kOnDZ3BOCs3cJf42NVe3mcO5vaXsLVqVh\n"
            "S1vrFtL/611kFvJcqtS33dj+e0NCTEIMwrL1Fz/NoVoh3kaH/wUtIxcHwAzIPRaM\n"
            "zyk8Ibn/DXqfjIAmxNleXO7aVnNvLeQqGfpJwz/Hwg1orgwXxd5TbskCgYEAzTFH\n"
            "KWTybOyQSzf6Y0TQGtCLCywrNW1Rs0uGywSZnCeT4AROIcGoJqSfAnjcfMGDtkHm\n"
            "lIUeK/7Lc11bn1kj1QwFt2WKRHv5bCd4hk0qNO62HwXpZhfBZ/Y2oyWRGqqZ+P+P\n"
            "ubmflD/eaow1YUqhKU6YMAbdppdGCTC31OUuY4cCgYBa+OCerzQCpJ2tfks1Z/Wu\n"
            "Gk4ehoobJc38eD0Vs++TjWoZ0ACDCrQuQ5wq+/1pN0HiraNkgodhmorJyV5F1ZhO\n"
            "manuIJjn/NuWOQTYYEJeRABfjpL/xc54syAXV4clHW9Fl4/uMJ0QihKu6T8mlaiD\n"
            "rbEl7taZEtHb6vduslNoUQKBgA3xLDmmz0YRaNiDjDLUiSNZSilPLfxqWiPJnPYM\n"
            "cPeIRObyw/BNPUSq6Nb9KVYcu/tVTPqIdP1eSaqkDEaugt3F/Flyv8tZdSAhKnJN\n"
            "qfGAysUe3LYAJTcQJrQ9KDfcoaumibh/4VTsZgttTW835+1rlrGktcjM/IhBVCxW\n"
            "CinfAoGBAKHqNWH54K9NDcPX7WXY72oIDNxyL2Nxd/46HToEEgjozyx+S+3yaGLU\n"
            "L7k/q6jabt+mDbRUgC+6BurOBZSZiE29KGKNyUbWI0LAuNyfktn/spDZbpdLxxLl\n"
            "v6Ndz6hfZyVNOolxvvdjoMH5i9+1h1POnRzTiTJS9tVGuJhw61Q3\n"
            "-----END RSA PRIVATE KEY-----\n"s;

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
            static std::unique_ptr<virtru::network::Service> Create(const std::string& url,
                                               std::string_view sdkConsumerCertAuthority,
                                               const std::string& clientKeyFileName,
                                               const std::string& clientCertFileName) { 
                BOOST_TEST_MESSAGE("Mock service constructed");
                LogTrace("Mock Service::Create");
            };

            virtual void executeGet(const std::string &url, const HttpHeaders &headers, HTTPServiceCallback &&callback, const std::string& ca, const std::string& key, const std::string& cert) override
            { 
              LogTrace("Mock Service::Get");

              callback(200, kasPubKey);
            }

            virtual void executePost(const std::string &url, const HttpHeaders &headers, std::string &&body, HTTPServiceCallback &&callback, const std::string& ca, const std::string& key, const std::string& cert) override
            { 
              LogTrace("Mock Service::Post");

              if (key == clientKeyFileName) {
                BOOST_TEST_MESSAGE("executePost key Passed");
              } else {
                LogDebug("key=" + key);
                LogDebug("clientKeyFileName=" + clientKeyFileName);
                BOOST_FAIL("executePost key fail");
              }

              if (cert == clientCertFileName) {
                BOOST_TEST_MESSAGE("executePost cert Passed");
              } else {
                LogDebug("cert=" + cert);
                LogDebug("clientCertFileName=" + clientCertFileName);
                BOOST_FAIL("executePost cert fail");
              }

              if (ca == certificateAuthorityFileName) {
                BOOST_TEST_MESSAGE("executePost ca Passed");
              } else {
                LogDebug("ca=" + ca);
                LogDebug("certificateAuthorityFileName=" + certificateAuthorityFileName);
                BOOST_FAIL("executePost ca fail");
              }

              const auto OIDCAccessToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJGRjJKM0o5TjNGQWQ0dnpLVDd2aEloZE1DTEVudE1PejVtLWhGNm5ScFNZIn0.eyJleHAiOjE2MTQxMTgzNzgsImlhdCI6MTYxNDExODA3OCwianRpIjoiNWQ4OTczYjYtYjg5Yy00OTBjLWIzYTYtMTM0ZDMxOTYxZTM3IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL2V4YW1wbGUtcmVhbG0iLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiN2ZkZGJkYWQtNDlmYS00NWU4LTg4MzItMzI3ZGI4ZjU1MDE1IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiZXhhbXBsZS1yZWFsbS1jbGllbnQiLCJzZXNzaW9uX3N0YXRlIjoiOTA0MTc4NTAtNWEwNC00ZmU1LTgxZWMtOTkzZDY1MmVhYmY5IiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIiwic3VwaXJpIjoidG9rZW5fc3VwaXJpIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJjbGFpbSI6eyJuYW1lIjp7InVzZXJuYW1lIjoiZm9vIn19LCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJqZWZmNS1leGFtcGxlIn0.NfM272HpLfyHACNJrXniyPF5klXjfB8QbhHBt_aTlZUF1-wO7W4-3qL02bMYe71dg_swR5WLFR0SL-zqa9zeKfsegL8E-lEeRSCcFwTvoSXPXSZ06tafFmSNxuA88MogG_3ZBhi9sUL5uAXtCoC3Rkb6xpb-JdHp42n68s_Mm1teCU2wx2rS6O1k23YCK3lY_xRsmV62sQ_tx973N5u7YHPxWsKVi-gHNlW3N0x23bRsEk-qcIq-3ug5cLOyADlNUeApTmug9lXGJxqxo3jlugnuf6VUtMwI1x8xSbePwC1pmGAfzZX2pS0kEUiGSHdH7flzibrMG70IXlutmS3e8Q";

              const auto xOIDCAccessToken = "aaaaaaaaa";



              callback(200, "{\""+std::string(kAccessToken)+"\" : \""+OIDCAccessToken+"\", \""+std::string(kRefreshToken)+"\" : \"bbbbb\"}");
            }

            virtual void executePatch(const std::string &url, const HttpHeaders &headers, std::string &&body, HTTPServiceCallback &&callback, const std::string& ca, const std::string& key, const std::string& cert) override
            { 
              std::cout << "executePatch: " << key << " " << cert << " " << ca << std::endl;

              if (key == clientKeyFileName) {
                BOOST_TEST_MESSAGE("executePatch key Passed");
              } else {
                LogDebug("key=" + key);
                LogDebug("clientKeyFileName=" + clientKeyFileName);
                BOOST_FAIL("executePatch key fail");
              }

              if (cert == clientCertFileName) {
                BOOST_TEST_MESSAGE("executePatch cert Passed");
              } else {
                LogDebug("cert=" + cert);
                LogDebug("clientCertFileName=" + clientCertFileName);
                BOOST_FAIL("executePatch cert fail");
              }

              if (ca == certificateAuthorityFileName) {
                BOOST_TEST_MESSAGE("executePatch ca Passed");
              } else {
                LogDebug("ca=" + ca);
                LogDebug("certificateAuthorityFileName=" + certificateAuthorityFileName);
                BOOST_FAIL("executePatch ca fail");
              }
              callback(0, "");
            }

    };

constexpr auto OIDC_ENDPOINT = "xhttps://localhost:8443";
constexpr auto KAS_URL = "xhttp://localhost:8080/kas";

void mkfile(const std::string& filename, const std::string& content)
{
    std::ofstream out(filename);
    out << content;
    out.close();
}

BOOST_AUTO_TEST_SUITE(test_oidc_pki) 

BOOST_AUTO_TEST_CASE(test_pki) {

    BOOST_TEST_MESSAGE("test_pki begin");

    Logger::getInstance().setLogLevel(virtru::LogLevel::Trace);
    Logger::getInstance().enableConsoleLogging();

    try {
        OIDCCredentials clientCreds;
        std::string clientID = "tdf-client";
        std::string organizationName = "organizationName";
        std::string oidcEndpoint = OIDC_ENDPOINT;

        LogTrace("Creating input files");
        mkfile(clientKeyFileName, privateKeyPem);
        mkfile(clientCertFileName, publicKeyX509);
        mkfile(certificateAuthorityFileName, caCert);

        LogTrace("Creating client credentials");
        clientCreds.setClientCredentialsPKI(clientID,
                                                clientKeyFileName,
                                                clientCertFileName,
                                                certificateAuthorityFileName,
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

        BOOST_TEST_MESSAGE("TDF pki test passed.");
    } catch (const Exception &exception) {
        BOOST_FAIL(exception.what());
    } catch (const std::exception &exception) {
        BOOST_FAIL(exception.what());
        std ::cout << exception.what() << std::endl;
    } catch (...) {
        BOOST_FAIL("Unknown exception...");
        std ::cout << "Unknown..." << std::endl;
    }
}

BOOST_AUTO_TEST_SUITE_END()
