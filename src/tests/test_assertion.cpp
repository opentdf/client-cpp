//
//  TDF SDK
//
//  Created by Sujan Reddy on 2023/10/08
//  Copyright 2023 Virtru Corporation
//

#define BOOST_TEST_MODULE test_assertion

#include "manifest_data_model.h"
#include "sdk_constants.h"
#include "crypto_utils.h"

#include <jwt-cpp/jwt.h>
#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(test_assertion_suite)

    using namespace std::string_literals;
    using namespace virtru;
    using namespace virtru::crypto;
    const auto publicKey =
            R"(-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIUKHT596VjugK4w53iZHtv74iB+agwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzEwMDkxNjQ0MDdaFw0yMzEx
MDgxNjQ0MDdaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQDV1ctGjTk/8kXwR76Lxhc5JJxhyy8ILk12DkPL4iB0
/DtrM/U5DZOovihHyDsjVNu1+B3jKw30OxZgu02/6HCKF4XOycEMZSbMrGnlJGBt
SrGDtP7t9A6hmP0M2LvbdbBF6pGW2NNLqseGSBnA6eqMxS+YiXBY75dKMTcyb7AK
cRicy557RyS+SbmvJTsFdBYf9B3wrfQXzTVmkhvX0hIazNtvX05ygXODLGH1sYw1
teR7XXAvWdYx1LLOM8Q0MIwe87aLBK1TLrJXLqzuru/urg9l+egailFUjdq5xl8F
3W8haku7GPh2XzyE++3hs3zdtJEj1D78AWnp7de5kPYz257MuClBbwZP7lXVOrmn
ysYvwzDy3Yr7g9E1sFpBABTdh2xAzwtRnMQrPAtwkYC24WT4h/oyeIxRQL39fecg
Rb6Thsh8sm6LUUBy3NR6TKQKXhqfLNfOMPJL/PKmbpIVxY/s9YRHbnVS5pVp3iPS
Neul6Fy6pyamVrfu8v1mRjyxZLGK48+6SXzeeXy9VPCmV7YT9jBx27otJ3F18bMj
XSNlYmkrpU4TP35pXquZOSc6coumiat+KuoaKPBZv891em4ZJUciWsLSuvbNyzyS
Zh21++3ZtS4dyT3xtYUOQhC+XubSdIwp9WoJ7h9CHxH1OfctnrEzZ5ZdO9oobbgm
LwIDAQABo1MwUTAdBgNVHQ4EFgQUnKOkphJrGOEdMnyip60aZr0Ar94wHwYDVR0j
BBgwFoAUnKOkphJrGOEdMnyip60aZr0Ar94wDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAgEAwd/LzE9zj1b7ymB4Nq5Q4HOvdjIrOK4OCSfVzpaV96wH
pNgvziaJuikghSWgqCuOBstL5RO+r4Whrf+9zdKE6JGS4oinZb2EMEhGzrFFC16z
S7DvOx9l0wDzcXYhnOpH0oW0ccLr7ftCMyp6dVDyDJTmpTihOIrC3esZ3UGqj0TS
jzAPM3nVc1k3nNesi+5vmI7u3YyKg2xPJdzP2QUqoUv+63K6hvhFzCdM7zN89cUN
Fg7oxIfcSc0EJXTklA87LExlD6SDBeMQhHmLMu7dZEbFOqyF6jllsefWYJx44ZMs
lCDQqT/6/5q6taqw9tOW+AQnj7DhhnjZ1E02zqHGywPAvz0ir5KwjELA8PG96iun
BaNjIfTYQeSVIhIfhbf7LlYq7dqe6+rieYQo5PAI3j2/581JbiV3U4RGk+vIrCQ1
OPgT0ZBT9Ak+R6HF7LOx/LSc0Q/DMr+MWOsOipymEXiCW/BgnR+EwXG6ldm+P6pl
CfZhE/U6fQc+NOP1KvjYU9NtJ8NRM/mXb46+SqlY5ws/4s5vUZvGD2CcCd3n1h7f
n+ByYlcCvyCzR43WpkkwBEs85qTWIDEeRJxsSndg0c3D5HoJeqqYqvbfFHimF2LQ
sT5TfTvgcot+rtzl1TLOc+iZ4PWmswoHcm33kljueeNtTeNyDRO6tFv8XXh9k/E=
-----END CERTIFICATE-----)";

    const auto privateKey =
            R"(-----BEGIN PRIVATE KEY-----
MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDV1ctGjTk/8kXw
R76Lxhc5JJxhyy8ILk12DkPL4iB0/DtrM/U5DZOovihHyDsjVNu1+B3jKw30OxZg
u02/6HCKF4XOycEMZSbMrGnlJGBtSrGDtP7t9A6hmP0M2LvbdbBF6pGW2NNLqseG
SBnA6eqMxS+YiXBY75dKMTcyb7AKcRicy557RyS+SbmvJTsFdBYf9B3wrfQXzTVm
khvX0hIazNtvX05ygXODLGH1sYw1teR7XXAvWdYx1LLOM8Q0MIwe87aLBK1TLrJX
Lqzuru/urg9l+egailFUjdq5xl8F3W8haku7GPh2XzyE++3hs3zdtJEj1D78AWnp
7de5kPYz257MuClBbwZP7lXVOrmnysYvwzDy3Yr7g9E1sFpBABTdh2xAzwtRnMQr
PAtwkYC24WT4h/oyeIxRQL39fecgRb6Thsh8sm6LUUBy3NR6TKQKXhqfLNfOMPJL
/PKmbpIVxY/s9YRHbnVS5pVp3iPSNeul6Fy6pyamVrfu8v1mRjyxZLGK48+6SXze
eXy9VPCmV7YT9jBx27otJ3F18bMjXSNlYmkrpU4TP35pXquZOSc6coumiat+Kuoa
KPBZv891em4ZJUciWsLSuvbNyzySZh21++3ZtS4dyT3xtYUOQhC+XubSdIwp9WoJ
7h9CHxH1OfctnrEzZ5ZdO9oobbgmLwIDAQABAoICAECFQlEW4pvTX9v44dst2asB
y3fMhXPr+K5y7mzx3YY+5zTZGBhvasrjGadTGNj3zVWSOH5nas3zGDT2vyZ1HaPl
Jhg3kxrI2JSwP0GHINtJStepQLSOy+1hipUaPlChKZ9nACfqY5L0xEBVuAOX8RAp
nUtiyPXk0RrvT67VuWHlLx58Z+Tdmg4ak77vtmfWV6irkW8iJcEax46b7m/H8HOK
tXlc4gA15CNDvIkUWfCI4hiBII0BB9rASXVjdEOlFFpwgfdfYWb0c5ZPvJlGSpoT
hgzog2qiqpifNsyQOPK9lj8YYiJhjfK1mL6tf2D3Nel1hsevTpPeX1VY0RsqTMba
uoa8NLCb2mVYSAl1GeOnPr26Zolnx3W4HHaC9AJOiPRSATQekQAVOOOJIfaxR80h
1SP6VQOQxfNgMMxFqDiWIN0zPmkgmNh7+mr08kXzIpP4zVs53evm6Ik3UZCqQDQ4
tAA24ia+Hsc8yrz8vofyw7vlYh9WCkqre43muPL9XCfNZxAkvCs1bd0zgOe2TJN5
i2JZmcC/kcyUtya/NfIoMBeOcf6ZO9bqih94ImxyqdM0PktL/iw5O5pkWmMVTriA
tb0eiMbUWx6v1Q/AmzbrcUupExReOJ6UhGCoXcgI3K2fUDiqOI/hMPty0nZeaVy/
kszzShWK70IAo8Zyw0FdAoIBAQDt3gotbsaJP0MTItAP/EOszsnJ3AqQU5+MBTIM
TaMidDaYZLWOvZctYuR4d3MXXO5zI8uyGlTmWkPBiGeeo2VdEZpfSD6E3HvjCu35
AL9FkW4ypCKcpRAS447cAZO2Fr3EXsjt7Z4JRdJXPdU2mStPX1AQ+XAgUOcUu8Ho
Ocv6Un/zN89xZLzP2icVXDLXzj1rRk17LVNXAI+kgxRKZCqKd+KPCvhl3kSIAPh3
GEilXdfKY+Tf3tKfPhnXzxQUF7/WSsbw5WQfpBtVmCwmevZOkZrh31DScmzIkSOP
Pu50OZjwb5CCaG+qqLzPiqhgGmydvR7EEknLTykwN0rkmcbbAoIBAQDmIsSQoFTk
5avc3vCEL3sHmN4DelYzysgNizYrhabPkkIPLIq615TZnW0v9IsdomvndSmAkTAP
Hg5Fl078sNrf2ohG61wGW4mLrONiYkRaZ9AByRgrv6FO8T1i4NofjYUv8YTUACZ4
HL7NoB6qR4melEaM971a9ZxiXdKIgPKae2Sa3zpdhovd1iEsoFqMGKHRzVf5VMPQ
mcrKLsnCpDJsnRsBR7m1RzhOPSG/52d6Qpmk2qZZnNGqjN1UvP//4cKvZDBn1+cW
MTjbM1vCU0cD+gdauallRHsm8Z+u61yBfsvy+EcCK5JYDWilJgHW8kM22Kb7Ggs2
IxW6Mi0TPIw9AoIBAQDpsJULIaPHvvEk4bTLn6jVI6u3t4hhVuaOZ6RN1hCJjub8
PSTqAXV+z4Nqnt/hehmB4Q8EAT6buN6MSniSsDCriNnC9nUFjp/f5SL62TMRI9nB
wuOGRdxO0mXN23bFE/6H6B87MZFrxr7pmwPXyg90wU0mAAmaliEQi43rmqy9V0QB
LTmOS8v74HU5VQVWY3aP59fDRjp0ZUa591V96H6q3zEkG0ECw6VMgLeaOa9VV6bj
XdTD5GPEsvwsu3MccmC0JW7hyFvfghigtQnbHD7T3dTuR7ldp7EcMwtedhNK+DM7
NEAi/nuGjJRCyhS1pgBD0ENjmhwJs9HhXtEjWbi1AoIBACm/qusVuvDfXWMvKnDA
cFA7giMdYV/57HrQg14328ASJ1u7V9t3WnBz56fodAhHO838ajABprdHW41yWojq
yHoNmeVLsyEQIA6vqXximUXRSWHZikH9fJTmnJ1AbzGEKeI9rTwMXu4xQMfqwUVg
vu1+tqHCG57RqbIKlTPgOKKfueuCjYMD8oGm49PFr0d0/H4kA06e+vrvu2McQ8vE
n8UmZwy/Z0gkiGlhG6tFnncGd/r5E250TXDkJw7FTqer2/aXdVSRTUGwYkEZuw6w
rtRg2k6yGbHeT30MHkzMM7bmOrd0JOWW4/CHVjGHiJPm1RyxBvHMkrYafUmO6rBv
rn0CggEBANlC/f0n+AMM5iRZYUDi9+xWBI63CtnQzgzDCxuW45q6+Xsu+BYadf/p
Rp6iDHhS/JYhVX5AI4pChB3DcQp6I4webXSxVp8QymMe+UctQWDej8B4cPXqHWGq
gTJoTJhp0IZ8ljwCjKA83uti/2sTHqK1z0sQmf8lHv35mFw5ymmU+JsFfTgPcHHG
UUZ/klWkmrsCwBaAR5UJznQTzDimni2kuvK82Km8UtaFsHwuZIhviq2P7kMJM/yM
vo21txY9PcjHxw87eTm3D1xWH4jgdKNpqJ6DQUW0Po5DqtASb7Ej6Kr3rMigQ8P8
JE0eO7WkIWzJwi55mw4G+WLobD9jZwk=
-----END PRIVATE KEY-----)";

    const auto manifestInJson =
            R"({
  "payload": {
    "type": "reference",
    "url": "0.payload",
    "protocol": "zip",
    "isEncrypted": true
  },
  "encryptionInformation": {
    "type": "split",
    "keyAccess": [
      {
        "type": "wrapped",
        "url": "http://kas.example.com:4000",
        "protocol": "kas",
        "wrappedKey": "Y4wTa8tdKqSS3DUNMKTIUQq8Ti/WFrq26DRemybBgBcL/CyUZ98hFjDQgy4csBusEqwQ5zG+UAoRgkLkHiAw7hNAayAUCVRw6aUYRF4LWfcs2BM9k6d3bHqun0v5w==",
        "policyBinding": "ZGMwNGExZjg0ODFjNDEzZTk5NjdkZmI5MWFjN2Y1MzI0MTliNjM5MmRlMTlhYWM0NjNjN2VjYTVkOTJlODcwNA==",
        "encryptedMetadata": "OEOqJCS6mZsmLWJ38lh6EN2lDUA8OagL/OxQRQ=="
      }
    ],
    "method": {
      "algorithm": "AES-256-GCM",
      "isStreamable": true,
      "iv": "OEOqJCS6mZsmLWJ3"
    },
    "integrityInformation": {
      "rootSignature": {
        "alg": "HS256",
        "sig": "YjliMzAyNjg4NzA0NzUyYmUwNzY1YWE4MWNhNDRmMDZjZDU3OWMyYTMzNjNlNDYyNTM4MDA4YjQxYTdmZmFmOA=="
      },
      "segmentSizeDefault": 1000000,
      "segmentHashAlg": "GMAC",
      "segments": [
        {
          "hash": "ZmQyYjY2ZDgxY2IzNGNmZTI3ODFhYTk2ZjJhNWNjODA=",
          "segmentSize": 14056,
          "encryptedSegmentSize": 14084
        }
      ],
      "encryptedSegmentSizeDefault": 1000028
    },
    "policy": "eyJ1dWlkIjoiNjEzMzM0NjYtNGYwYS00YTEyLTk1ZmItYjZkOGJkMGI4YjI2IiwiYm9keSI6eyJhdHRyaWJ1dGVzIjpbXSwiZGlzc2VtIjpbInVzZXJAdmlydHJ1LmNvbSJdfX0="
  }
})";

    BOOST_AUTO_TEST_CASE(test_sign_assertion) {
        try {
            // Add handling assertion
            Assertion handlingAssertion{AssertionType::Handling, Scope::TDO};
            handlingAssertion.setId("assertion1");
            handlingAssertion.setAppliesToState(AppliesToState::unencrypted);

            StatementGroup statementGroup{StatementType::HandlingStatement};
            statementGroup.setValue("            <edh:Edh xmlns:edh=\"urn:us:gov:ic:edh\"\n"
                                    "                     xmlns:usagency=\"urn:us:gov:ic:usagency\"\n"
                                    "                     xmlns:icid=\"urn:us:gov:ic:id\"\n"
                                    "                     xmlns:arh=\"urn:us:gov:ic:arh\"\n"
                                    "                     xmlns:ism=\"urn:us:gov:ic:ism\"\n"
                                    "                     xmlns:ntk=\"urn:us:gov:ic:ntk\"\n"
                                    "                     usagency:CESVersion=\"201609\"\n"
                                    "                     icid:DESVersion=\"1\"\n"
                                    "                     edh:DESVersion=\"201609\"\n"
                                    "                     arh:DESVersion=\"3\"\n"
                                    "                     ism:DESVersion=\"201609.201707\"\n"
                                    "                     ism:ISMCATCESVersion=\"201709\"\n"
                                    "                     ntk:DESVersion=\"201508\">\n"
                                    "                <icid:Identifier>guide://999990/something</icid:Identifier>\n"
                                    "                <edh:DataItemCreateDateTime>2012-05-28T15:06:00Z</edh:DataItemCreateDateTime>\n"
                                    "                <edh:ResponsibleEntity edh:role=\"Custodian\">\n"
                                    "                    <edh:Country>USA</edh:Country>\n"
                                    "                    <edh:Organization>DNI</edh:Organization>\n"
                                    "                </edh:ResponsibleEntity>\n"
                                    "                <arh:Security ism:compliesWith=\"USGov USIC\"\n"
                                    "                              ism:resourceElement=\"true\"\n"
                                    "                              ism:createDate=\"2012-05-28\"\n"
                                    "                              ism:classification=\"U\"\n"
                                    "                              ism:ownerProducer=\"USA\"/>\n"
                                    "            </edh:Edh>");
            handlingAssertion.setStatementGroup(statementGroup);

            auto assertionAsJson = ManifestDataModel::assertionAsJson(handlingAssertion);
            auto hash = calculateSHA256(toBytes(assertionAsJson));
            auto base64Hash = base64Encode(toBytes(hash));
            BOOST_TEST(base64Hash == "lKszB8GjW5UeLVJ7AwPfiFGIB3FxKe4J1b/OMiIVMEM=");

            handlingAssertion.setAssertionHash(base64Hash);
            assertionAsJson = ManifestDataModel::assertionAsJson(handlingAssertion);

            std::cout << "JWT token payload" << assertionAsJson << std::endl;

            auto token = jwt::create()
                    .set_type("JWT")
                    .set_payload_claim(kAssertion, jwt::claim(assertionAsJson))
                    .sign(jwt::algorithm::rs256("", privateKey));

            auto verify = jwt::verify()
                    .allow_algorithm(jwt::algorithm::rs256(publicKey, ""));

            auto decoded_token = jwt::decode(token);
            verify.verify(decoded_token);

            auto decodeToken = decoded_token.get_payload_claim(kAssertion);
            std::cout << "JWT token payload" << decoded_token.get_payload() << std::endl;
            BOOST_TEST(assertionAsJson == decodeToken.as_string());
    } catch ( const std::exception& exception) {
        BOOST_FAIL(exception.what());
        std::cout << exception.what() << std::endl;
    } catch ( ... ) {
        BOOST_FAIL("Unknown exception...");
        std::cout << "Unknown..." << std::endl;
    }

    }

BOOST_AUTO_TEST_SUITE_END()
