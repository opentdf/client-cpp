//
//  TDF SDK
//
//  Created by Sujan Reddy on 2022/04/05.
//  Copyright 2022 Virtru Corporation
//

#define BOOST_TEST_MODULE test_metadata_in_tdf

#include "tdf_client.h"
#include "network/http_client_service.h"
#include "tdf_exception.h"
#include "oidc_credentials.h"
#include "support/test_utils.h"
#include "tdf_storage_type.h"

#include <boost/test/included/unit_test.hpp>
#include <boost/endian/arithmetic.hpp>
#include <boost/filesystem.hpp>
#include <iostream>

#ifdef _WINDOWS
#include <direct.h>
#define GetCurrentDir _getcwd
#else
#include <unistd.h>
#define GetCurrentDir getcwd
#endif

using namespace virtru::network;
using namespace virtru;

using HttpHeaders = std::unordered_map<std::string, std::string>;
using HTTPServiceCallback = std::function<void(unsigned int statusCode, std::string &&response)>;
const auto kasPubKey = "\"-----BEGIN CERTIFICATE-----\nMIIDsjCCApqgAwIBAgIUYmcYT3eh9l8K/zgMhY+N6+5BX8gwDQYJKoZIhvcNAQEM\nBQAwcDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkRDMRMwEQYDVQQHDApXYXNoaW5n\ndG9uMQ8wDQYDVQQKDAZWaXJ0cnUxDDAKBgNVBAMMA2thczEgMB4GCSqGSIb3DQEJ\nARYRZGV2b3BzQHZpcnRydS5jb20wIBcNMTkwMzIyMDQ1MTA2WhgPMzAxODA3MjMw\nNDUxMDZaMHAxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJEQzETMBEGA1UEBwwKV2Fz\naGluZ3RvbjEPMA0GA1UECgwGVmlydHJ1MQwwCgYDVQQDDANrYXMxIDAeBgkqhkiG\n9w0BCQEWEWRldm9wc0B2aXJ0cnUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\nMIIBCgKCAQEAp0gprQxQTjj6furvVQnK3m6u7YpEjZNl5ze66MUjaD7dMYislTyq\nBoqUeLQ0w7xhqoJYGobQfweWLmzIuuntwemAYtBgRt5a5nImJsYQCLA1YEOhXMBo\niVV6qC8be9bzus1j+EDpB+HCn0nQZXnc617Kob3o/Z1FNfoSum+r1h8Og86lsA5G\np3oIMRtYNZF57UI/K858Dyyo/7AI2AFtoUQLYUDS9nFtU6cdX4HuNYvwaxV4P0Mt\nirXyG5xd/T6/Uf1iGqy1Xd8jYOM/2Tbe9feZ/LeWQHvJaBOvZZrpt58xTu3QTBEA\nCqNNoAQ+jP4/h/aXYB2HBe1wB3MLXLvIYwIDAQABo0IwQDAdBgNVHQ4EFgQUBmyt\nQTHTdqx5KqP7ip12Xey+UWUwHwYDVR0jBBgwFoAUBmytQTHTdqx5KqP7ip12Xey+\nUWUwDQYJKoZIhvcNAQEMBQADggEBAHghOOSNq/so2GXAftnU43tDzmDxcegxE4Yf\nIBfOqepkMVSZiCSz4c66HxtuYQGDqvreWBcPj17HLS6XAbujIzVb8DM8EDQl1sB7\nc7DC5Uwg095nu7TLSsYdzNGw+1bMq7eOyNWDNDY3/kEekK2h1FhzUsWQZwPuLm8c\nJK/w/MkL+icoACuBxteueRvc7tugVCjE2J/xkvmBzvRuUqOYZgY0CdqNkO6lMZeV\nSczhTPJ8W5TO6LfSfvG1W62CjrQ7IjtE4dFr3Lz1HsnyhxmfxJ4oKH7E31lYgmj/\niYWvx/RskN/+Byt19t84htwM0zr1uinCb1NF+xkOsha22AKJ9Rc=\n-----END CERTIFICATE-----\n\"";

std::string getCurrentWorkingDir() {
    char buff[FILENAME_MAX];
    GetCurrentDir( buff, FILENAME_MAX );
    std::string current_working_dir(buff);
    return current_working_dir;
}

bool endsWith(std::string const &str, std::string const &suffix) {
    if (str.length() < suffix.length()) {
        return false;
    }
    return std::equal(suffix.rbegin(), suffix.rend(), str.rbegin());
}

class MockNetwork : public INetwork {
public:
    /// Constructor
    explicit MockNetwork(const std::string& rewrapMock): m_rewrapMock(rewrapMock) {}

    /// Destructor
    ~MockNetwork() override = default;
public: //INetwork members
    // Assuming /kas_public_key is only GET request
    virtual void executeGet(const std::string &/*url*/,
                            const HttpHeaders &/*headers*/,
                            HTTPServiceCallback &&callback,
                            const std::string& /*ca*/,
                            const std::string& /*key*/,
                            const std::string& /*cert*/) override {
        callback(200, kasPubKey);
    }

    virtual void executePost(const std::string &url,
                             const HttpHeaders &/*headers*/,
                             std::string &&/*body*/,
                             HTTPServiceCallback &&callback,
                             const std::string& /*ca*/,
                             const std::string& /*key*/,
                             const std::string& /*cert*/) override {


        // Handle 'auth/realms/tdf/protocol/openid-connect/token' request
        if (endsWith(url, "/openid-connect/token")) {
            static const auto response = R"({"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ0a0FFQXVDVDRnajV6MTA0eElEME5lSjkzRjJJOUJ5QkEwZzM2VkFabnI4In0.eyJleHAiOjE2NDkxNzk1ODUsImlhdCI6MTY0OTE3OTI4NSwianRpIjoiMTEzZmUwMTctMzY1MS00MzliLTk4MmMtNTIwN2EzYjk2YzkzIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo2NTQzMi9hdXRoL3JlYWxtcy90ZGYiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiMDVlNjQ4MmQtN2ZmOS00MjdiLTljYjktMDgwMzdiMGU0NzI4IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGRmLWNsaWVudCIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL2tleWNsb2FrLWh0dHAiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtdGRmIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsImNsaWVudEhvc3QiOiIxMC4yNDQuMC44IiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJjbGllbnRJZCI6InRkZi1jbGllbnQiLCJ0ZGZfY2xhaW1zIjp7ImNsaWVudF9wdWJsaWNfc2lnbmluZ19rZXkiOiItLS0tLUJFR0lOIFBVQkxJQyBLRVktLS0tLVxuTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFxcHN2ZCtrMWNqT1VFSHd2cFBHeFxuQ3o3VWM3V2RKczdxSVdBNzFoRk12M0hVZVNVekg5UE1OZXFxSStiK2JXZG1YRTIzT3RxNmpzOUNtVURsOWpHZ1xuTEVsYytzLzNPVE1MQjNLZkpJZVdHWm5yQ001R0pPa1NSV3d4ZVlaemhQK0VSZnBSb1RTeVVIaCs2dGRHK3hEQVxuN05xVXFZbjUxcVdHR25xZ3dDZzBNNGhzeHc0ZmZOQWU0VHg0aHFUYVpQSlBSRVlhZHdjcDZrZjhhQjQ4d0VkOFxuVWc2RUMwbGRQVENzN1dqZmNENi9OckdrTmNWdVRUMXo2aWlra2U0VXJ5Y3FPVzExUGU4T0lVMGNDTXdXeTUrRFxuUGtrMWxxNzROZ3l0Rk9MZktqbUs1N2k4RVlWZ0xVYTJzN1V2VFZ3VE11SHhYdkoyeUxxMFYvcWRxQlZnNWlOQ1xuaVFJREFRQUJcbi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLVxuIiwiZW50aXRsZW1lbnRzIjpbXX0sInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10ZGYtY2xpZW50IiwiY2xpZW50QWRkcmVzcyI6IjEwLjI0NC4wLjgifQ.VwvILTPndwEpRm4-YSjtyg1YM01aJVe6M7EJDUf4-UtNn92L-kcLewai-eS0l50Az4TKmo3LFvXS2ryeasD_iTiKoaXeqRGavmRQA92HFjtUdw6S4nfjC_xKDFjoUQERXbkWI6TgrJCVt5xWrMpVPoVleCdZFRWWryuIMUwvoZasFUIqHApq7tAhuLvFYWBuXQvTqYmj8t2GkFqJuXKCbCdWp0qATphrOMj60PPp7ra-sqv66SApRSihO5qxhRIrkA61z39ctj6jlkIkcJ-bX3Pp_kPlrSlToaVC73Zmpra93Q6wJIZGyQMNXk22SSIKhgEZOKaQoZJ-H2YNR14wOQ","expires_in":300,"refresh_expires_in":0,"token_type":"Bearer","not-before-policy":0,"scope":"email profile"})";
            callback(200, response);
        } else if(endsWith(url, "/rewrap")) {
            callback(200, m_rewrapMock.c_str());
        } else {
            BOOST_FAIL("MockNetwork failed handle the post request");
        }
    }

    virtual void executePatch(const std::string &/*url*/,
                              const HttpHeaders &/*headers*/,
                              std::string &&/*body*/,
                              HTTPServiceCallback &&/*callback*/,
                              const std::string& /*ca*/,
                              const std::string& /*key*/,
                              const std::string& /*cert*/) override { // Do nothing};
    }

    virtual void executeHead(const std::string &/*url*/,
                            const HttpHeaders &/*headers*/,
                            HTTPServiceCallback &&callback,
                            const std::string& /*ca*/,
                            const std::string& /*key*/,
                            const std::string& /*cert*/) override {
        callback(400, "");
    }

    virtual void executePut(const std::string &/*url*/,
                              const HttpHeaders &/*headers*/,
                              std::string &&/*body*/,
                              HTTPServiceCallback &&callback,
                              const std::string& /*ca*/,
                              const std::string& /*key*/,
                              const std::string& /*cert*/) override {
        callback(400, "");
    }
private:
    std::string m_rewrapMock;

};

BOOST_AUTO_TEST_SUITE(test_metadata_in_tdf_suite)

    using namespace virtru;

    const auto rsa2048PublicKey =
            R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy6B+BSrO8pfeMXAvs4nE
xIvKvhu3MqY51dmuuVNFADinouYBLiz5PyozeVO1mqf73aqyLOpwbZ0/eCafji4U
FO/ZzhRpYFQrgvVVDZGaPtZfSKLwwhhbECp+JgQQqjJeqTWpoWb8UeJe9vwQGF/7
xZgnE3ustWOOUpR1Kxf+AsJixdkhF9b9plyWynZsgen845MD1L8HmeEhWSLo7GXG
tIrjOL8IIHjkCxhOl6PnzQ3cJ7JYFNwmFIPkW0ER2xYhJOZANf54jSc/0tYLJwwo
OD62lTpVmZYbG+B+MQDRJLGSN2D/pGpzNe71zTVMOKTg0IZCZrW1VMNKDd6gyEgY
0QIDAQAB
-----END PUBLIC KEY-----)";

    const auto rsa2048PrivateKey =
            R"(-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDLoH4FKs7yl94x
cC+zicTEi8q+G7cypjnV2a65U0UAOKei5gEuLPk/KjN5U7Wap/vdqrIs6nBtnT94
Jp+OLhQU79nOFGlgVCuC9VUNkZo+1l9IovDCGFsQKn4mBBCqMl6pNamhZvxR4l72
/BAYX/vFmCcTe6y1Y45SlHUrF/4CwmLF2SEX1v2mXJbKdmyB6fzjkwPUvweZ4SFZ
IujsZca0iuM4vwggeOQLGE6Xo+fNDdwnslgU3CYUg+RbQRHbFiEk5kA1/niNJz/S
1gsnDCg4PraVOlWZlhsb4H4xANEksZI3YP+kanM17vXNNUw4pODQhkJmtbVUw0oN
3qDISBjRAgMBAAECggEATyL6lwuCDioTgmc1QrNiM3iYvLWMxzRu+bt1+jRwdpuO
GvMEtmtoGrJN+vMbexWZ/xYd1PLv6snYJtvr2pfx2gk1PrAUHAnaNzUdbv6NUaqC
sXoR030ftvKswB2IVHzq6Rwf5shde31cpuRjZPW4pZxyY1IHVx9v6owj1TGn2G39
kO2GmKO9s88AvxFsM/xAIkmEPKO9KJLyc5qAATuzlHC37iCbQ9mA3tsvJsf2VVHG
xld6PRFoQgJmlaoX91WSLvHhLlQNPIAszsuUkJYjTF8bQpJsnqxJJSQSyh9SJBbr
+EH2Uf7lHt8Ej9HnCJ7F5mHeWK2eSV1GIcjiYFxJgQKBgQD0W3S70PdxG628iy4w
WQA5chjzs5xtonHij4GX0l17MkaRMNZ/7yfS8ck3ZTvPZjQwbE5EGiTW61NSWPVz
WKS8xnCl8N50FWVxxKtVNv9NOFGzmi6LHG3RUL76UknDlB9ZuKvCgYOp+LHjhNis
DgHgtNCB5k5RFkDdYtgkbIs8WQKBgQDVVDqMQMyMkPzsZg6wqEZ+PxrA90NE86Ja
w6FSHAaEjqBsqFuVEtBn/x2J9cR+TnH7vLHtdVJ75NYGTIFlXXWy4e0l/1vD5PUc
w+0LP87m6kWVyhSfuIJ89YOS4l9ddNHStM2oM1AMqfglpxQCI4rps/ICu4Ecz8WC
m+DVPLvROQKBgQDtlR5inkJ3jtnVP92g1GgLcowgJropPpBMIAt4eei6J5/E+x8T
NIwb5Uomuh71AAIuMp/GR0UaUaOppSTBCabihG5yaUdgxozjmLydFeQUSHXnkjk+
uF1t7nxBFlDx/8qbiZo2e4ZwdIVBGaExaE0bFbLFGg97d4+JsNlGUOLvwQKBgCPa
10hRb8/EYq487QUmE0sOwilipazGIiiNLuUFDtdivXXlyhbBJcQE7esNIqxz9NZx
vZoCmQ13xb0jSLBHyAt7y4cSZ1MCfWwLRiEY5WaMQ4vMfjDmKxBjl2ytnYewpb97
YgF+NlsaijmR3lwJq0RiWS+6YhX8md684koUviCJAoGBAKDs5Hxb4TpzFAE3eD7B
eTxMYhKtSwVLg9OGDxxxkg6m3bfuSOgSKbC17IxcEBwky54IlkJS9uqIIvwEokzP
zgxp/lGe3KyjeOM4NOPVeMxYDPYb5+rYzrnnTX5yBhqZqOIkzaFAtALFUYNUagbB
DCzGcDpkNVkPR58v1BvBs4zZ
-----END PRIVATE KEY-----)";

    BOOST_AUTO_TEST_CASE(test_with_metadata_case) {
        std::string currentDir = getCurrentWorkingDir();
        const std::string metaData = R"({"displayName" : "opentdf c++ sdk"})";

    // TODO: BUGBUG: We should use std::filesystem once all the compilers catch up.
#ifdef _WINDOWS
        std::string tdfFilepath {currentDir };
        tdfFilepath.append("\\data\\sample_with_metadata.txt.tdf");
#else
        std::string tdfFilepath{currentDir};
        tdfFilepath.append("/data/sample_with_metadata.txt.tdf");
#endif

        OIDCCredentials clientCreds;
        clientCreds.setClientCredentialsClientSecret("dummy_client_id", "dummy_secret",
                                                     "dummy.org", "http://dummyhost.org/");
        auto oidcClientTDF = std::make_unique<TDFClient>(clientCreds,
                                                         "http://dummyhost.org/");

        static const auto rewrapResponse = R"({"entityWrappedKey":"uQ3iEZ6qYVUe6xy3lsr0c51K9cykioJlVl8X5qn00eqoAt59ul53JpgqLHl5C8rOuu1NPWLoWGEAKxt1Fia3L6k0LM8o7rBvWaUbyp5Jo5puCHrzlwsy00f9AvuXNkyV6Z8M/Bup2+0814ro4uOgBR4lL1fDyvC1AUk3Z71NETIAdH5BfzXbxS+swmbxKWsx0QnJViP1U9Tt3SuQmeOcayX85OePVN6mQwhfxyDJTKCyrggUPd/vLc/VnFJEdSv4Js2LPQhvvUSAbTD1FawbSVg1O1lJBz25f8RerV66Ekhmij7vavrL8UvyOu0WWafA3rjmjwp7wCf+lto4Ophnlg==","metadata":{}})";
        std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>(rewrapResponse);

        oidcClientTDF->setHTTPServiceProvider(mockNetwork);
        oidcClientTDF->setPrivateKey(rsa2048PrivateKey);
        oidcClientTDF->setPublicKey(rsa2048PublicKey);

        TDFStorageType fileStorageType;
        fileStorageType.setTDFStorageFileType(tdfFilepath);
        auto metaDataFromTDF = oidcClientTDF->getEncryptedMetadata(fileStorageType);
        BOOST_TEST(metaData == metaDataFromTDF);
    }

    BOOST_AUTO_TEST_CASE(test_without_metadata_case) {

        std::string currentDir = getCurrentWorkingDir();

        // TODO: BUGBUG: We should use std::filesystem once all the compilers catch up.
#ifdef _WINDOWS
        std::string tdfFilepath {currentDir };
        tdfFilepath.append("\\data\\sample_without_metadata.txt.tdf");
#else
        std::string tdfFilepath{currentDir};
        tdfFilepath.append("/data/sample_without_metadata.txt.tdf");
#endif

        OIDCCredentials clientCreds;
        clientCreds.setClientCredentialsClientSecret("dummy_client_id", "dummy_secret",
                                                     "dummy.org", "http://dummyhost.org/");
        auto oidcClientTDF = std::make_unique<TDFClient>(clientCreds,
                                                         "http://dummyhost.org/");
        static const auto rewrapResponse = R"({"entityWrappedKey":"H8bbJjwuc+iiTc6AO1gdXtK+OCovR7dqNayFmNSETc0CU1Wr43L8Mct82NmK91FOWnEq+9zo9tog0ARA1qkeWM90+hmodcQFVDunHGCqdxuZpHTgXALTc4hahC3Ux1/pm60IOXIxsoue0QziQXA93vKjHtnNvIjaE3hNCXpR9cKGa/Duyc6gvGU7KRrV/8hXdQT86gDJ6CD1nFQQ8INFD9Hk8meyxepfA5M0mGqk0eX8PKG1xsMTTp7U66ZEFw+XI/W3xYhZ0HIXYH5CSc68QHDkbpw767vx7HMZqZCjpz30dxcdk4l3xczLRNDNJNZwL8cVpjGRDtKRlH/xon9eWw==","metadata":{}})";
        std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>(rewrapResponse);

        oidcClientTDF->setHTTPServiceProvider(mockNetwork);
        oidcClientTDF->setPrivateKey(rsa2048PrivateKey);
        oidcClientTDF->setPublicKey(rsa2048PublicKey);

        TDFStorageType fileStorageType;
        fileStorageType.setTDFStorageFileType(tdfFilepath);
        auto metaDataFromTDF = oidcClientTDF->getEncryptedMetadata(fileStorageType);
        std::string emptyMetadata{};
        BOOST_TEST(emptyMetadata == metaDataFromTDF);
    }

    BOOST_AUTO_TEST_CASE(test_xml_format_metadata_case) {
        std::string currentDir = getCurrentWorkingDir();

        // TODO: BUGBUG: We should use std::filesystem once all the compilers catch up.
#ifdef _WINDOWS
        std::string tdfFilepath {currentDir };
        tdfFilepath.append("\\data\\sample_xml_format.tdf");
#else
        std::string tdfFilepath{currentDir};
        tdfFilepath.append("/data/sample_xml_format.tdf");
#endif

        OIDCCredentials clientCreds;
        clientCreds.setClientCredentialsClientSecret("dummy_client_id", "dummy_secret",
                                                     "dummy.org", "http://dummyhost.org/");
        auto oidcClientTDF = std::make_unique<TDFClient>(clientCreds,
                                                         "http://dummyhost.org/");
        std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>(std::string());
        oidcClientTDF->setHTTPServiceProvider(mockNetwork);

        TDFStorageType fileStorageType;
        fileStorageType.setTDFStorageFileType(tdfFilepath);
        BOOST_CHECK_THROW(oidcClientTDF->getEncryptedMetadata(fileStorageType), virtru::Exception);
    }

    BOOST_AUTO_TEST_CASE(test_decrypt_file_partial) {
        std::string currentDir = getCurrentWorkingDir();

        // TODO: BUGBUG: We should use std::filesystem once all the compilers catch up.
#ifdef _WINDOWS
        std::string tdfFileName {currentDir };
        tdfFileName.append("\\data\\8mbfile.txt.tdf");
#else
        std::string tdfFileName{currentDir};
        tdfFileName.append("/data/8mbfile.txt.tdf");
#endif

        OIDCCredentials clientCreds;
        clientCreds.setClientCredentialsClientSecret("dummy_client_id", "dummy_secret",
                                                     "dummy.org", "http://dummyhost.org/");
        auto oidcClientTDF = std::make_unique<TDFClient>(clientCreds,
                                                         "http://dummyhost.org/");
        static const auto rewrapResponse = R"({"entityWrappedKey":"V16tn/TrhnrPXIdeWt57eU5WTINl21IXR0Vb7v+5k50jpy0ecS79FEwBPy4jWthE2MX64wGyZWLbleAyABvmwI/9DO4VvRU4SQ7VtJDqWG9JJn6pLkOuD4238M+Z1CF8Ewmb1UICo6qqm5O9CF+8BJjtlDHf1Q5jKOr/+3nod5T6E8M4iWIcTJwUdQBSE1pD1vuKJMiVRqRQX5QCELGlUDXhyzBhVHCvFkIkdbcSyzOKgQxJkiPeUjXlrSCERbYz5+w9fgJ4epxcCmnwnyqZ/K7HQmoBEpzrYhCeSSf5e3FQtc1nTu80qk9RpKrjjcBRMtps2/gudbhnl/7N1HbcSg==","metadata":{}})";
        std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>(rewrapResponse);

        oidcClientTDF->setHTTPServiceProvider(mockNetwork);
        oidcClientTDF->setPrivateKey(rsa2048PrivateKey);
        oidcClientTDF->setPublicKey(rsa2048PublicKey);

        TDFStorageType tdfStorageFileType;
        tdfStorageFileType.setTDFStorageFileType(tdfFileName);

        auto segmentSize = 1024*1024;
        {
            auto plainData = oidcClientTDF->decryptDataPartial(tdfStorageFileType, segmentSize - 1, 2);
            std::string strPlainData(plainData.begin(), plainData.end());
            BOOST_TEST(strPlainData == "ab");
        }


        {
            auto plainData = oidcClientTDF->decryptDataPartial(tdfStorageFileType,(segmentSize*6) - 1, 2);
            std::string strPlainData(plainData.begin(), plainData.end());
            BOOST_TEST(strPlainData == "fg");
        }

        {
            auto plainData = oidcClientTDF->decryptDataPartial(tdfStorageFileType, (segmentSize*7), 2);
            std::string strPlainData(plainData.begin(), plainData.end());
            BOOST_TEST(strPlainData == "hh");
        }


        {
            auto plainData = oidcClientTDF->decryptDataPartial(tdfStorageFileType, 0, 10);
            std::string strPlainData(plainData.begin(), plainData.end());
            BOOST_TEST(strPlainData == "aaaaaaaaaa");
        }


        {
            auto plainData = oidcClientTDF->decryptDataPartial(tdfStorageFileType, 3 * segmentSize, segmentSize + 1);
            std::string strPlainData(plainData.begin(), plainData.end());
            std::string expectedData(segmentSize, 'd');
            expectedData.append("e");
            if (expectedData != strPlainData) {
                BOOST_FAIL("decryptFilePartial test failed");
            }
        }

        // Expect exception the request length is not valid
        auto longLength = 6 * segmentSize;
        BOOST_CHECK_THROW(oidcClientTDF->decryptDataPartial(tdfStorageFileType, 3 * segmentSize, longLength),
                          virtru::Exception);

        { // 10 bytes

#ifdef _WINDOWS
           std::string tdfFileName {currentDir };
           tdfFileName.append("\\data\\10bytes.txt.tdf");
#else
           std::string tdfFileName{currentDir};
           tdfFileName.append("/data/10bytes.txt.tdf");
#endif

            static const auto rewrapResponse = R"({"entityWrappedKey":"vw9p1/+apWVHkFibA3w8Tg8tpPlV0F1D40mfH3BLXLdLk9SHVTEHabJiBz8QvgStEcxVTWinf/B7m0T8+JoDzCvItIcJ+EjzWjZ0xUCtQPdwpGajbTFlLQj9PyjW8ldZnLsOoKgSyOP5dtYL3/O5ExG6baBN+NtxZR+sOyIIoK4PAmb22cm5yO4MLjN9LIpIyhC5X3jSXx+83X8/pdBV7vP+gd6mZ+wVN4KXGPrNI8t3LmmmN9cHqQJzswUAsy19WE8LkK59HJez/kPMd8+icEQX61rA8LUmpljZJUx+3mwGGUjcPc5XSy7wIHgsFR4uMD0F6SgJeix5kzCUqucLiA==","metadata":{}})";
            std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>(rewrapResponse);

            oidcClientTDF->setHTTPServiceProvider(mockNetwork);

            TDFStorageType tdfStorageFileType;
            tdfStorageFileType.setTDFStorageFileType(tdfFileName);

            {
                auto plainData = oidcClientTDF->decryptDataPartial(tdfStorageFileType, 0, 1);
                std::string strPlainData(plainData.begin(), plainData.end());
                BOOST_TEST(strPlainData == "x");
            }

            {
                auto plainData = oidcClientTDF->decryptDataPartial(tdfStorageFileType, 1, 9);
                std::string strPlainData(plainData.begin(), plainData.end());
                BOOST_TEST(strPlainData == "xxxxxxxxx");
            }

            {
                auto plainData = oidcClientTDF->decryptDataPartial(tdfStorageFileType, 0, 10);
                std::string strPlainData(plainData.begin(), plainData.end());
                BOOST_TEST(strPlainData == "xxxxxxxxxx");
            }
        }

        { // 4mb

#ifdef _WINDOWS
            std::string tdfFileName {currentDir };
            tdfFileName.append("\\data\\4mbfile.txt.tdf");
#else
            std::string tdfFileName{currentDir};
            tdfFileName.append("/data/4mbfile.txt.tdf");
#endif

            static const auto rewrapResponse = R"({"entityWrappedKey":"EVNnw2MXpLCg51tUM2m53yKT5htq0SxkKCMj8lY9QVpBWWi3dxOGot7XmWHwaPtc9C3dwGxpKZ7GIM2ugNfImdctcRN4yokaIlM19Kt+c0L3DNANsYN8wLgjxvDeClMSFtJ42cycSBN5Nm/Q+/wBXwcVNcWypY73Uytr5mhNuVJ6MB2FHsYn5aV2tNCwvn2KGqWrffEnV/2p+aLClx9Yp+Q2N0Hqn3MSgwNMp94QYmBZceNSCCbAh63RtW/8+iNKylZZeBjq7iwK/oKbdXR+YXuTV2fW7w1xoMYoeC4DJwxPKj9HucW3xbQFOpp2tPG/0mmN85X6MYYy5eFXxfY7sA==","metadata":{}})";
            std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>(rewrapResponse);

            oidcClientTDF->setHTTPServiceProvider(mockNetwork);

            TDFStorageType tdfStorageFileType;
            tdfStorageFileType.setTDFStorageFileType(tdfFileName);

            {
                auto plainData = oidcClientTDF->decryptDataPartial(tdfStorageFileType, segmentSize - 1, 2);
                std::string strPlainData(plainData.begin(), plainData.end());
                BOOST_TEST(strPlainData == "ab");
            }

            {
                auto plainData = oidcClientTDF->decryptDataPartial(tdfStorageFileType, 0, 10);
                std::string strPlainData(plainData.begin(), plainData.end());
                BOOST_TEST(strPlainData == "aaaaaaaaaa");
            }

            {
                auto plainData = oidcClientTDF->decryptDataPartial(tdfStorageFileType, 3 * segmentSize, segmentSize + 1);
                std::string strPlainData(plainData.begin(), plainData.end());
                std::string expectedData(segmentSize, 'd');
                expectedData.append("e");
                if (expectedData != strPlainData) {
                    BOOST_FAIL("decryptFilePartial test failed");
                }
            }


            // Expect exception the request length is not valid
            auto longLength = 2 * segmentSize;
            BOOST_CHECK_THROW(oidcClientTDF->decryptDataPartial(tdfStorageFileType, 3 * segmentSize, longLength),
                              virtru::Exception);
        }

        { // 4mb string partial

#ifdef _WINDOWS
            std::string tdfFileName {currentDir };
            tdfFileName.append("\\data\\4mbfile.txt.tdf");
#else
            std::string tdfFileName{currentDir};
            tdfFileName.append("/data/4mbfile.txt.tdf");
#endif

            std::vector<VBYTE> fileData;

            // Read file from memory.
            std::ifstream ifs(tdfFileName.data(), std::ios::binary|std::ios::ate);
            if (!ifs) {
                BOOST_FAIL("Failed to open file for reading.");
            }

            std::ifstream::pos_type pos = ifs.tellg();
            fileData.reserve(ifs.tellg());
            ifs.seekg(0, std::ios::beg);
            std::for_each(std::istreambuf_iterator<char>(ifs),
                          std::istreambuf_iterator<char>(),
                          [&fileData](const char c){
                              fileData.push_back(c);
                          });

            static const auto rewrapResponse = R"({"entityWrappedKey":"EVNnw2MXpLCg51tUM2m53yKT5htq0SxkKCMj8lY9QVpBWWi3dxOGot7XmWHwaPtc9C3dwGxpKZ7GIM2ugNfImdctcRN4yokaIlM19Kt+c0L3DNANsYN8wLgjxvDeClMSFtJ42cycSBN5Nm/Q+/wBXwcVNcWypY73Uytr5mhNuVJ6MB2FHsYn5aV2tNCwvn2KGqWrffEnV/2p+aLClx9Yp+Q2N0Hqn3MSgwNMp94QYmBZceNSCCbAh63RtW/8+iNKylZZeBjq7iwK/oKbdXR+YXuTV2fW7w1xoMYoeC4DJwxPKj9HucW3xbQFOpp2tPG/0mmN85X6MYYy5eFXxfY7sA==","metadata":{}})";
            std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>(rewrapResponse);

            oidcClientTDF->setHTTPServiceProvider(mockNetwork);

            TDFStorageType tdfStorageBufferType;
            tdfStorageBufferType.setTDFStorageBufferType(fileData);

            {
                auto plainData = oidcClientTDF->decryptDataPartial(tdfStorageBufferType, segmentSize - 1, 2);
                std::string strPlainData(plainData.begin(), plainData.end());
                BOOST_TEST(strPlainData == "ab");
            }

            {
                auto plainData = oidcClientTDF->decryptDataPartial(tdfStorageBufferType, 0, 10);
                std::string strPlainData(plainData.begin(), plainData.end());
                BOOST_TEST(strPlainData == "aaaaaaaaaa");
            }

            {
                auto plainData = oidcClientTDF->decryptDataPartial(tdfStorageBufferType, 3 * segmentSize, segmentSize + 1);
                std::string strPlainData(plainData.begin(), plainData.end());
                std::string expectedData(segmentSize, 'd');
                expectedData.append("e");
                if (expectedData != strPlainData) {
                    BOOST_FAIL("decryptFilePartial test failed");
                }
            }


            // Expect exception the request length is not valid
            auto longLength = 2 * segmentSize;
            BOOST_CHECK_THROW(oidcClientTDF->decryptDataPartial(tdfStorageBufferType, 3 * segmentSize, longLength),
                              virtru::Exception);
        }
    }

BOOST_AUTO_TEST_SUITE_END()