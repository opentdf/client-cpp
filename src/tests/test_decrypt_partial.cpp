//
//  TDF SDK
//
//  Created by Pat Mancuso on 2022/03/07.
//  Copyright 2022 Virtru Corporation
//

#define BOOST_TEST_MODULE test_tdf_decrypt_partial

#include <iostream>
#include <fstream>
#include <memory>
#include <iomanip>

#include "tdf_exception.h"
#include "logger.h"
#include "tdf_client.h"
#include "crypto/crypto_utils.h"
#include "stdlib.h"
#include "openssl/sha.h"
#include "network/http_client_service.h"

#include "boost/test/included/unit_test.hpp"

using namespace virtru;

BOOST_AUTO_TEST_SUITE(test_decrypt_partial)
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
            "-----END PUBLIC KEY-----\n"s;


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

    using HttpHeaders = std::unordered_map<std::string, std::string>;

    // callback once the http request is completed.
    using HTTPServiceCallback = std::function<void(unsigned int statusCode, std::string &&response)>;

    class MockNetwork : public INetwork {
        int m_rewrap = 0;
        int m_token = 0;
    public: //INetwork members
        static std::unique_ptr<virtru::network::Service> Create(const std::string& /*url*/,
                                                                std::string_view /*sdkConsumerCertAuthority*/,
                                                                const std::string& /*clientKeyFileName*/,
                                                                const std::string& /*clientCertFileName*/) {
            BOOST_TEST_MESSAGE("Mock service constructed");
            LogTrace("Mock Service::Create");
            return 0;
        };

        virtual void executeGet(const std::string &url, const HttpHeaders &/*headers*/, HTTPServiceCallback &&callback, const std::string& /*ca*/, const std::string& /*key*/, const std::string& /*cert*/) override
        {
            LogTrace("Mock Service::Get");

            std::string response1 = "\"-----BEGIN CERTIFICATE-----\\nMIICmDCCAYACCQCKQT/wtuNxsTANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANr\\nYXMwHhcNMjIwNDAxMTgyOTMxWhcNMjMwNDAxMTgyOTMxWjAOMQwwCgYDVQQDDANr\\nYXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCxTMLlymloUDvo9zde\\nKUNzBheJqeDP6B2AoBsLUQW6lOFmec5pKVxzs8RZfdzBj7+kW0X3a/3afklEICLV\\n0Go4Uu1rdeXvxbdug+8cGxzULOCfmFQxOGEMVa5v2V+KgolXIwtBU1zC/O7L6hPO\\nYhD5oRxA4fK4XvDW5eIUgQpiA2LiBjeEfBs8s5yqygohTqnm4jOSrLUYgsaYtA7S\\n6LFwZ2XvVSQu7pQw8YkN4kQD3pzvrJ8gKYyZmZzvDh817nNLzirZS7tlIun7WVEz\\nf29UCQ6JtSUE+9ZTQeTF8wsvwh1/rLxIM4Nhnm2b8bI6eXXSpyJQKPXESckT70gk\\nLCxRAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAK/4zP3K9id0amq9Yhziqf6UFoT9\\ni0GLVDz5+TTh40DgP4E/i0IXdxsKljUYpvsqCqZCwwygkAB3ceIWqRo/hsIdjKc5\\nr9ziOA40CQu3bb8/o46bcVsQg9M+tcfdUDYPpUG5ydkGrGHmAPJ0ItebNyY7pXkB\\nsJJsfGEjL80TTZqIYwQWNKP2RTCAxz+1LJ8c/P5Zeol7WvjTENYSVXER3uXdTO+n\\n7E0HESlUZiMhayJO+r9xvzRqK2AO0ntGa/aCle89diIZAcYK1R+3WUku1wJ2sO8D\\nSfsc+9qV/POo7RC6OF1Kao5+nFxS6Feqr0+lD14yPHL/LMzkGJd0ifMVyHs=\\n-----END CERTIFICATE-----\"\n";

            std::string response2 = "405 {\"error\":\"RESTEASY003650: No resource method found for GET, return 405 with Allow header\"}";

            if (url.find("api/kas/kas_public_key") != std::string::npos) {
                callback(200, response1.c_str());
            } else if (url.find("auth/realms/tdf/protocol/openid-connect/token") != std::string::npos) {
                callback(405, response2.c_str());
            } else {
                callback(404, "Not found");
            }
        }

        virtual void executePost(const std::string &url, const HttpHeaders &/*headers*/, std::string &&/*body*/, HTTPServiceCallback &&callback, const std::string& /*ca*/, const std::string& /*key*/, const std::string& /*cert*/) override
        {
            LogTrace("Mock Service::Post");

            std::string token_response1 = "{\"access_token\":\"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJqZmJwMGNKTEF2ZEYwdnZTU1NEZ1c0ZWs2X1NfU2FwQ25qNWJKVHhXU1IwIn0.eyJleHAiOjE2NTAzMDY5MDgsImlhdCI6MTY1MDMwNjYwOCwianRpIjoiMWIwMTBlN2YtMzhjYS00OGUwLWJjNzAtZDNlM2Y3NzNhY2RlIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo2NTQzMi9hdXRoL3JlYWxtcy90ZGYiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiZGRlOTFmYjQtM2FmOS00N2ZjLTk5OTktNmZlYWIxNGI1NTQ1IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGRmLWNsaWVudCIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL2tleWNsb2FrLWh0dHAiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtdGRmIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsImNsaWVudEhvc3QiOiIxMC4yNDQuMC4xMCIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiY2xpZW50SWQiOiJ0ZGYtY2xpZW50IiwidGRmX2NsYWltcyI6eyJjbGllbnRfcHVibGljX3NpZ25pbmdfa2V5IjoiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1cbk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdkVwMlA5cm5wZWY1ZjFLbXErUHpcbjhTUENvMVVmcUVuYWJBSVJXVUUvbS9uU1U5dTZEWXV0bkZTY0kwQkcvcG1KbW8vT0lpRkU4YnhvblNHWTFFdjJcbjQ2VWNzWVNQcm9KZUlPK3JILzFXV2R4WFRnRVVhTksydzJrbjdJQ0JwUzlQOHU2Ujk1UkJXUHRGaW9tU0Q4bjZcbndqSWxoOWNyRjZwcEp1amtQTVVVR3UyenB0ZkxmcDlMUStiUWZ0bHI5cTVPTXpQQWlFTnNqOUZ1WXhQYUl3UXhcbkZkZ1BwK0RjTTkwdFRBeGtOYWtCSlZ6Q1dIcUtrMnZZcnlMMVhYa3JWU0dWTGN4T1BYYnhVUmhleFkzSVNMajNcbjZBSHlZVzc4UDVVNjBCT0p3STluTk1yK2dBcCsyTFhSQXRxd0ZaWXhBVmdIQ0dDZEF5Vk5FZUJxMVF3VXgrc1RcbmtRSURBUUFCXG4tLS0tLUVORCBQVUJMSUMgS0VZLS0tLS1cbiIsImVudGl0bGVtZW50cyI6W119LCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJzZXJ2aWNlLWFjY291bnQtdGRmLWNsaWVudCIsImNsaWVudEFkZHJlc3MiOiIxMC4yNDQuMC4xMCJ9.QPn1mlE0W3SYQntPqkEhKTiWEJ3M_yZibvRyKfbgN4PRsmfsdqkIyO4Smbiz2LuL4rbBoWKdoOMgdrwtYFUP78wb7DM_T3DYeRKRY1_JxfJQ5zQd1LX_EKARjZX-1fYTP0aYzwlI0jK-rTWBCo0fwXQv9tzK8ufenl0mg5UBi-QU96It9RAUVClucE-6xSnIjISZFsI-GuNxOsaj1-7SZsZlmQ36sCMRi8dQdNIbpDMamBk3UwOsSqk0s9r13ryVJ78OiJ04xRdzqeDNPhcc7xQB1kyoPh61rsTWzff0dacSi695aAQWcDeCNzh8cWVS55M9_SZ6HeeIxbM-6CO0gA\",\"expires_in\":300,\"refresh_expires_in\":0,\"token_type\":\"Bearer\",\"not-before-policy\":0,\"scope\":\"email profile\"}";

            std::string rewrap_response1 = "{\"entityWrappedKey\":\"TqFu0SY5ViAswG6qlquXa2sFWPGrfCKWEcnn4HZZCfJi4f34mclALXtzMRq7cA00ynObYBoA3hGSULDVW3QQlVMXP15/es5x4iZVPHYNJcKfPbI4JsW4IU8av19CdRHbXqJXu8jvCJyDtIyY+SfHnhc+UlZHfKrrC5RFvOVwLlxeSwjp5ySs9PMLP7uCQlW8XEHrwB5nDvpUsx9fyL4spn3qhtS12Mp1rm9kYpCES0QVLKTNQFtt8CvciflelXqTu/lp/Y5lsa89FS7bF2IG25Eyi9seu59Y8oeDNTiNlBr1kIuOx1Mb/mZK7yob6xieyoY3e3nmPz8FiLNbr7ojfA==\",\"metadata\":{}}";

            if (url.find("auth/realms/tdf/protocol/openid-connect/token") != std::string::npos) {
                m_token++;
                if (m_token == 1) {
                    callback(200, token_response1.c_str());
                } else if (m_token == 2) {
                    callback(200, token_response1.c_str());
                } else {
                    callback(404, "Not found");
                }
            } else if (url.find("api/kas/v2/rewrap") != std::string::npos) {
                m_rewrap++;
                if (m_rewrap == 1) {
                    callback(200, rewrap_response1.c_str());
                } else {
                    callback(404, "Not found");
                }
            } else {
                callback(404, "Not found");
            }
        }

        virtual void executePatch(const std::string &/*url*/, const HttpHeaders &/*headers*/, std::string &&/*body*/, HTTPServiceCallback &&callback, const std::string& /*ca*/, const std::string& /*key*/, const std::string& /*cert*/) override
        {
            LogTrace("Mock Service::Patch");

            callback(404, "Not found");
        }

    };


    const std::string sequentialNumbersData {"\
000001002003004005006007008009\
010011012013014015016017018019\
020021022023024025026027028029\
030031032033034035036037038039\
040041042043044045046047048049\
050051052053054055056057058059\
060061062063064065066067068069\
070071072073074075076077078079\
080081082083084085086087088089\
090091092093094095096097098099"};

std::string getOidcEndpoint() {return "http://localhost:65432";};
std::string getKasUrl() {return "http://localhost:65432/api/kas";};
std::string getClientId() {return "tdf-client";};
std::string getClientSecret() {return "123-456";};
std::string getOrgName() {return "tdf";};

std::string makeEscapedString(const std::string inString)
{
    std::string result;

    for (uint8_t c:inString) {
        std::stringstream hexVal;
        hexVal << "\\x";
        hexVal << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned>(c);
        result += hexVal.str();
    }
    return result;
}

// To capture values for the mock network to return,
// set USE_MOCK_NETWORK to 0, build and run, capture the
// server responses and the encrypted tdf (from the logger output)
// and paste them into the appropriate string constants in this file
// then set it to 1 again, build again, and it should only talk to the mock network
#define USE_MOCK_NETWORK 1

BOOST_AUTO_TEST_CASE(test_tdf_decrypt_string_partial) {
    bool result = false;

    Logger::getInstance().enableConsoleLogging();
    Logger::getInstance().setLogLevel(virtru::LogLevel::Trace);

    LogTrace("Creating credentials");
    OIDCCredentials creds;
    creds.setClientCredentialsClientSecret(getClientId(), getClientSecret(), getOrgName(), getOidcEndpoint());

    LogTrace("Creating client");
    auto client = new TDFClient(creds, getKasUrl());

#if USE_MOCK_NETWORK
    LogTrace("Creating mock network");
    std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>();

    LogTrace("setting mock network");
    client->setHTTPServiceProvider(mockNetwork);
#endif

    LogTrace("Setting known keys");
    // Use known keys so the mock replay is valid
    client->setPrivateKey(privateKeyPem);
    client->setPublicKey(publicKeyPem);

    unsigned long offset = 10;
    unsigned long length = 10;

    LogTrace("Decrypting partial string");

#if USE_MOCK_NETWORK
    std::string encryptedString = "\x50\x4b\x03\x04\x0a\x00\x08\x00\x00\x00\xc4\x73\x92\x54\x00\x00\x00\x00\x48\x01\x00\x00\x48\x01\x00\x00\x09\x00\x18\x00\x30\x2e\x70\x61\x79\x6c\x6f\x61\x64\x55\x54\x05\x00\x01\x30\xae\x5d\x62\x75\x78\x0b\x00\x01\x04\x00\x00\x00\x00\x04\x00\x00\x00\x00\x71\x0a\x87\x3b\x23\xb6\x8a\x1e\x89\x9e\x13\x56\x58\x35\xb4\xaa\x64\xb3\xf6\x55\x83\xe6\x97\x99\x35\xcc\xa5\x89\xc4\x25\x76\x43\x97\xc9\xae\x32\x15\x38\xf4\xaa\x69\xb4\xf7\x98\xb4\x53\x47\xf4\x89\x8a\xe0\xfe\x7c\x69\x50\x65\x4e\x71\xd4\x85\xdc\x91\xd4\x68\x4b\xb6\x6e\x7d\x96\x46\x24\x37\x3b\x94\x53\x8e\x4b\x1d\xee\xa2\x6b\x73\x98\x83\xb8\x35\x46\xd3\xac\xfe\x79\x9b\x48\xed\xa2\x65\xd6\xe3\x47\x44\x2a\x58\x51\xe5\xbe\x13\x4d\x32\x58\x8f\x33\x23\xcb\x2a\x20\x33\xcb\x30\x8d\x50\x37\x62\x98\xc2\x9d\xc3\x04\xf3\x8d\xbc\x61\x2b\x43\xfb\xbf\xa9\x99\x0b\x12\x74\xac\xb0\xcf\x66\xc7\x74\xfd\x09\x14\xbd\x06\xe5\xd1\x70\x53\xa9\xc9\x02\xc1\x30\x15\x9d\x15\x46\xa9\x69\xb5\xd1\x36\x28\x16\x3b\x6b\x3f\xc5\x3a\x9c\xb0\xc4\x09\xf9\xa4\xc2\x06\xcd\x8b\x4c\x47\x5d\x05\x91\x65\xd2\x2b\x75\x6a\xdc\xb1\xf3\xb1\xa5\xba\x09\xf9\xa5\xc6\x15\x1f\x7e\x38\xce\x35\xaf\x40\xad\x21\x35\x88\x3b\xeb\xda\x8e\x0b\xbe\xee\x49\x79\xfd\x3a\x76\x5c\x7e\x91\x93\x62\xf2\xf4\x32\xba\xef\xb3\x04\x95\x35\x3f\x20\x69\x43\xba\xe8\x8e\x04\x38\x94\xaf\x5b\xcd\x93\x54\x14\x6f\x33\xd4\xe2\x27\x1e\xe3\x02\x1b\x8d\xa1\xab\xfb\x05\xee\x1d\xeb\x1c\x5f\xf9\x45\x22\x17\x0d\xfa\xfc\x2b\xe9\x0a\x9b\x93\x29\xd8\xe6\x0f\x64\xce\xe4\x86\x7a\x47\x14\xba\xad\x47\x70\x47\x13\x7e\xaa\xb6\x03\x65\xb8\xd6\xc6\x90\x5b\x29\x8f\xa9\x68\xae\x8f\x4d\x19\x36\x81\x50\x4b\x07\x08\x79\xea\xf3\x42\x48\x01\x00\x00\x48\x01\x00\x00\x50\x4b\x03\x04\x0a\x00\x08\x00\x00\x00\xc4\x73\x92\x54\x00\x00\x00\x00\x11\x05\x00\x00\x11\x05\x00\x00\x0f\x00\x18\x00\x30\x2e\x6d\x61\x6e\x69\x66\x65\x73\x74\x2e\x6a\x73\x6f\x6e\x55\x54\x05\x00\x01\x30\xae\x5d\x62\x75\x78\x0b\x00\x01\x04\x00\x00\x00\x00\x04\x00\x00\x00\x00\x7b\x22\x65\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e\x49\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e\x22\x3a\x7b\x22\x69\x6e\x74\x65\x67\x72\x69\x74\x79\x49\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e\x22\x3a\x7b\x22\x65\x6e\x63\x72\x79\x70\x74\x65\x64\x53\x65\x67\x6d\x65\x6e\x74\x53\x69\x7a\x65\x44\x65\x66\x61\x75\x6c\x74\x22\x3a\x31\x30\x34\x38\x36\x30\x34\x2c\x22\x72\x6f\x6f\x74\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x22\x3a\x7b\x22\x61\x6c\x67\x22\x3a\x22\x48\x53\x32\x35\x36\x22\x2c\x22\x73\x69\x67\x22\x3a\x22\x4e\x32\x5a\x6d\x4d\x47\x45\x77\x4e\x6a\x67\x35\x59\x54\x6b\x33\x59\x6a\x45\x79\x4d\x57\x56\x68\x4d\x6d\x56\x6a\x4f\x54\x42\x6a\x4e\x44\x55\x35\x4e\x32\x55\x32\x4e\x6d\x49\x33\x5a\x6d\x59\x78\x4e\x44\x45\x32\x59\x7a\x68\x69\x59\x7a\x46\x6a\x5a\x6d\x45\x33\x5a\x44\x52\x6b\x59\x7a\x41\x32\x4e\x7a\x52\x69\x4e\x57\x59\x34\x4e\x47\x55\x79\x4d\x41\x3d\x3d\x22\x7d\x2c\x22\x73\x65\x67\x6d\x65\x6e\x74\x48\x61\x73\x68\x41\x6c\x67\x22\x3a\x22\x47\x4d\x41\x43\x22\x2c\x22\x73\x65\x67\x6d\x65\x6e\x74\x53\x69\x7a\x65\x44\x65\x66\x61\x75\x6c\x74\x22\x3a\x31\x30\x34\x38\x35\x37\x36\x2c\x22\x73\x65\x67\x6d\x65\x6e\x74\x73\x22\x3a\x5b\x7b\x22\x65\x6e\x63\x72\x79\x70\x74\x65\x64\x53\x65\x67\x6d\x65\x6e\x74\x53\x69\x7a\x65\x22\x3a\x33\x32\x38\x2c\x22\x68\x61\x73\x68\x22\x3a\x22\x4e\x6a\x56\x69\x4f\x47\x51\x32\x59\x7a\x59\x35\x4d\x44\x56\x69\x4d\x6a\x6b\x34\x5a\x6d\x45\x35\x4e\x6a\x68\x68\x5a\x54\x68\x6d\x4e\x47\x51\x78\x4f\x54\x4d\x32\x4f\x44\x45\x3d\x22\x2c\x22\x73\x65\x67\x6d\x65\x6e\x74\x53\x69\x7a\x65\x22\x3a\x31\x30\x34\x38\x35\x37\x36\x7d\x5d\x7d\x2c\x22\x6b\x65\x79\x41\x63\x63\x65\x73\x73\x22\x3a\x5b\x7b\x22\x70\x6f\x6c\x69\x63\x79\x42\x69\x6e\x64\x69\x6e\x67\x22\x3a\x22\x4f\x54\x46\x68\x4d\x54\x5a\x6c\x4e\x6d\x4e\x68\x4e\x7a\x49\x77\x4f\x54\x45\x77\x4d\x6d\x49\x77\x4e\x7a\x49\x7a\x4e\x32\x49\x30\x4e\x44\x6c\x6b\x4d\x6d\x45\x31\x4d\x44\x41\x32\x59\x6d\x51\x35\x4f\x54\x59\x35\x5a\x6a\x67\x7a\x4f\x54\x4d\x7a\x59\x7a\x5a\x6a\x4e\x44\x56\x6c\x4f\x44\x63\x35\x4d\x6a\x67\x35\x4e\x47\x45\x31\x4f\x54\x6c\x6c\x4e\x77\x3d\x3d\x22\x2c\x22\x70\x72\x6f\x74\x6f\x63\x6f\x6c\x22\x3a\x22\x6b\x61\x73\x22\x2c\x22\x74\x79\x70\x65\x22\x3a\x22\x77\x72\x61\x70\x70\x65\x64\x22\x2c\x22\x75\x72\x6c\x22\x3a\x22\x68\x74\x74\x70\x3a\x2f\x2f\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x3a\x36\x35\x34\x33\x32\x2f\x61\x70\x69\x2f\x6b\x61\x73\x22\x2c\x22\x77\x72\x61\x70\x70\x65\x64\x4b\x65\x79\x22\x3a\x22\x5a\x30\x32\x52\x37\x33\x2b\x31\x54\x34\x34\x36\x6b\x6c\x4b\x45\x32\x62\x67\x46\x58\x31\x35\x47\x33\x41\x70\x7a\x45\x33\x6c\x46\x35\x54\x63\x6a\x59\x74\x64\x52\x38\x34\x63\x47\x69\x59\x71\x63\x79\x78\x47\x7a\x57\x6d\x69\x67\x37\x77\x32\x39\x30\x63\x72\x6d\x44\x55\x76\x55\x57\x49\x2b\x79\x62\x4a\x4c\x56\x4f\x36\x49\x30\x65\x52\x2f\x33\x48\x4c\x38\x70\x38\x51\x37\x58\x50\x54\x57\x39\x48\x42\x75\x76\x6b\x32\x57\x44\x42\x4c\x4a\x47\x76\x43\x79\x36\x73\x35\x49\x72\x73\x46\x47\x73\x6e\x70\x2b\x2b\x46\x56\x75\x44\x45\x78\x67\x42\x65\x7a\x57\x6a\x78\x79\x78\x62\x45\x7a\x41\x35\x4f\x34\x6c\x2f\x48\x4c\x55\x6b\x4a\x65\x63\x6a\x33\x4e\x54\x74\x38\x77\x54\x45\x6a\x34\x30\x68\x49\x6d\x76\x61\x75\x4c\x34\x49\x4e\x63\x6f\x44\x73\x64\x48\x74\x72\x42\x5a\x39\x5a\x44\x79\x74\x42\x4e\x4c\x72\x73\x54\x51\x6d\x75\x42\x33\x69\x68\x6e\x2b\x72\x33\x6b\x6c\x67\x6c\x79\x75\x4e\x59\x75\x46\x5a\x67\x79\x6b\x36\x75\x4e\x65\x70\x35\x6a\x5a\x59\x57\x75\x46\x69\x37\x47\x51\x71\x32\x57\x37\x5a\x53\x75\x6a\x2b\x2f\x36\x6c\x6e\x72\x47\x49\x31\x77\x2f\x4b\x71\x71\x34\x38\x56\x4f\x70\x66\x36\x49\x49\x63\x41\x33\x2f\x75\x50\x41\x66\x57\x63\x7a\x31\x59\x41\x71\x51\x35\x78\x31\x5a\x42\x2f\x6d\x2b\x78\x68\x4a\x46\x6d\x71\x38\x44\x65\x73\x48\x68\x42\x4b\x78\x61\x50\x49\x39\x6a\x34\x30\x79\x48\x54\x53\x79\x65\x54\x6d\x64\x4b\x6f\x50\x37\x4a\x78\x2b\x46\x6e\x75\x79\x74\x4e\x6c\x6c\x41\x41\x3d\x3d\x22\x7d\x5d\x2c\x22\x6d\x65\x74\x68\x6f\x64\x22\x3a\x7b\x22\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x22\x3a\x22\x41\x45\x53\x2d\x32\x35\x36\x2d\x47\x43\x4d\x22\x2c\x22\x69\x73\x53\x74\x72\x65\x61\x6d\x61\x62\x6c\x65\x22\x3a\x74\x72\x75\x65\x2c\x22\x69\x76\x22\x3a\x22\x59\x33\x67\x39\x38\x30\x5a\x54\x7a\x59\x54\x4e\x44\x31\x2b\x62\x22\x7d\x2c\x22\x70\x6f\x6c\x69\x63\x79\x22\x3a\x22\x65\x79\x4a\x69\x62\x32\x52\x35\x49\x6a\x70\x37\x49\x6d\x52\x68\x64\x47\x46\x42\x64\x48\x52\x79\x61\x57\x4a\x31\x64\x47\x56\x7a\x49\x6a\x70\x62\x58\x53\x77\x69\x5a\x47\x6c\x7a\x63\x32\x56\x74\x49\x6a\x70\x62\x58\x58\x30\x73\x49\x6e\x56\x31\x61\x57\x51\x69\x4f\x69\x49\x78\x4f\x44\x4a\x6d\x4d\x6a\x63\x7a\x5a\x43\x30\x34\x4e\x32\x45\x35\x4c\x54\x52\x68\x5a\x57\x4d\x74\x59\x57\x56\x6b\x59\x69\x30\x79\x59\x7a\x46\x6d\x4e\x57\x51\x30\x4e\x54\x52\x6c\x4f\x47\x45\x69\x66\x51\x3d\x3d\x22\x2c\x22\x74\x79\x70\x65\x22\x3a\x22\x73\x70\x6c\x69\x74\x22\x7d\x2c\x22\x70\x61\x79\x6c\x6f\x61\x64\x22\x3a\x7b\x22\x69\x73\x45\x6e\x63\x72\x79\x70\x74\x65\x64\x22\x3a\x74\x72\x75\x65\x2c\x22\x6d\x69\x6d\x65\x54\x79\x70\x65\x22\x3a\x22\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x6f\x63\x74\x65\x74\x2d\x73\x74\x72\x65\x61\x6d\x22\x2c\x22\x70\x72\x6f\x74\x6f\x63\x6f\x6c\x22\x3a\x22\x7a\x69\x70\x22\x2c\x22\x74\x79\x70\x65\x22\x3a\x22\x72\x65\x66\x65\x72\x65\x6e\x63\x65\x22\x2c\x22\x75\x72\x6c\x22\x3a\x22\x30\x2e\x70\x61\x79\x6c\x6f\x61\x64\x22\x7d\x7d\x50\x4b\x07\x08\x95\x2d\x2a\xc3\x11\x05\x00\x00\x11\x05\x00\x00\x50\x4b\x01\x02\x0a\x03\x0a\x00\x08\x00\x00\x00\xc4\x73\x92\x54\x79\xea\xf3\x42\x48\x01\x00\x00\x48\x01\x00\x00\x09\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\xed\x81\x00\x00\x00\x00\x30\x2e\x70\x61\x79\x6c\x6f\x61\x64\x55\x54\x05\x00\x01\x30\xae\x5d\x62\x75\x78\x0b\x00\x01\x04\x00\x00\x00\x00\x04\x00\x00\x00\x00\x50\x4b\x01\x02\x0a\x03\x0a\x00\x08\x00\x00\x00\xc4\x73\x92\x54\x95\x2d\x2a\xc3\x11\x05\x00\x00\x11\x05\x00\x00\x0f\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\xed\x81\x97\x01\x00\x00\x30\x2e\x6d\x61\x6e\x69\x66\x65\x73\x74\x2e\x6a\x73\x6f\x6e\x55\x54\x05\x00\x01\x30\xae\x5d\x62\x75\x78\x0b\x00\x01\x04\x00\x00\x00\x00\x04\x00\x00\x00\x00\x50\x4b\x05\x06\x00\x00\x00\x00\x02\x00\x02\x00\xa4\x00\x00\x00\xfd\x06\x00\x00\x00\x00"s;
#else
    std::string encryptedString(client->encryptString(sequentialNumbersData));
    LogDebug("Encrypted string="+makeEscapedString(encryptedString));
#endif

    std::string decryptedSubstring{client->decryptStringPartial(encryptedString, offset, length)};

    std::string plaintextSubstring{sequentialNumbersData.substr(offset, length)};

    result = (decryptedSubstring == plaintextSubstring);

    delete client;
    BOOST_TEST(result);
}

BOOST_AUTO_TEST_SUITE_END()
