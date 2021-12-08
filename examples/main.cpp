#include <iostream>
#include <unordered_map>

#include "network_interface.h"
#include "tdf.h"
#include "tdf_constants.h"
#include "tdf_exception.h"
#include "tdfbuilder.h"

int main() {

    using namespace virtru;

    constexpr auto user = "sreddy@trusteddataformat.org";
    const auto OIDCAccessToken = R"(eyJhbGciOiJSUzI1NiIsInR5cCIg
OiAiSldUIiwia2lkIiA6ICJGRjJKM0o5TjNGQWQ0dnpLVDd2aEloZE1DTEVudE1PejVtLWhGNm5ScFNZIn0.
eyJleHAiOjE2MTQxMTgzNzgsImlhdCI6MTYxNDExODA3OCwianRpIjoiNWQ4OTczYjYtYjg5Yy00OTBjLWIz
YTYtMTM0ZDMxOTYxZTM3IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL2V4YW1w
bGUtcmVhbG0iLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiN2ZkZGJkYWQtNDlmYS00NWU4LTg4MzItMzI3ZGI4
ZjU1MDE1IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiZXhhbXBsZS1yZWFsbS1jbGllbnQiLCJzZXNzaW9uX3N0
YXRlIjoiOTA0MTc4NTAtNWEwNC00ZmU1LTgxZWMtOTkzZDY1MmVhYmY5IiwiYWNyIjoiMSIsInJlYWxtX2Fj
Y2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJj
ZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50
LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIiwic3VwaXJpIjoidG9r
ZW5fc3VwaXJpIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJjbGFpbSI6eyJuYW1lIjp7InVzZXJuYW1lIjoi
Zm9vIn19LCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJqZWZmNS1leGFtcGxlIn0.NfM272HpLfyHACNJrXniyPF5
klXjfB8QbhHBt_aTlZUF1-wO7W4-3qL02bMYe71dg_swR5WLFR0SL-zqa9zeKfsegL8E-lEeRSCcFwTvoSXP
XSZ06tafFmSNxuA88MogG_3ZBhi9sUL5uAXtCoC3Rkb6xpb-JdHp42n68s_Mm1teCU2wx2rS6O1k23YCK3lY
_xRsmV62sQ_tx973N5u7YHPxWsKVi-gHNlW3N0x23bRsEk-qcIq-3ug5cLOyADlNUeApTmug9lXGJxqxo3jl
ugnuf6VUtMwI1x8xSbePwC1pmGAfzZX2pS0kEUiGSHdH7flzibrMG70IXlutmS3e8Q)";
    constexpr auto kasUrl = "api.virtru.com";

    try {
        std::ostringstream authHeaderValue;
        HttpHeaders headers = {
        {"Accept", "application/json; charset=utf-8"},
        {"Authentication", std::string("Bearer ") + OIDCAccessToken}
    };

        auto tdfbuilderPtr = std::unique_ptr<TDFBuilder>(new TDFBuilder(user));
        auto tdf = tdfbuilderPtr->setHttpHeaders(headers)
                        .setKasUrl(kasUrl)
                        .enableOIDC(true)
                        .enableConsoleLogging(LogLevel::Debug)
                        .setDefaultSegmentSize(2 * 1024 * 1024)
                        .setIntegrityAlgorithm(IntegrityAlgorithm::HS256, IntegrityAlgorithm::GMAC)
                        .setKeyAccessType(KeyAccessType::Wrapped)
                        .build();

        tdf->encryptFile("", "");

    } catch (const Exception &exception) {
        std ::cout << "virtru exception " << exception.what() << std::endl;
    } catch (const std::exception &exception) {
        std ::cout << exception.what() << std::endl;
    } catch (...) {
        std ::cout << "Unknown..." << std::endl;
    }
}
