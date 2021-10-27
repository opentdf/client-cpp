//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/19
//  Copyright 2019 Virtru Corporation
//

#define BOOST_TEST_MODULE test_jwt_suite

#include <jwt/jwt.h>
#include <chrono>

#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(test_tdf_suite)

    using namespace std::string_literals;

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

    BOOST_AUTO_TEST_CASE(test_tdf_suite_rsa) {

        // Generate a token which expires in a min.
        std::chrono::system_clock::time_point nextMin = std::chrono::system_clock::now() + std::chrono::seconds(60);
        auto timeSinceEpoch = std::chrono::duration_cast<std::chrono::seconds>(nextMin.time_since_epoch()).count();

        try {
            auto token = jwt::create()
                    .set_expires_at(nextMin)
                    .sign(jwt::algorithm::rs256(rsa2048PublicKey, rsa2048PrivateKey, "", ""));

            std::cout << "JWT Token: " << token << std::endl;

            std::ostringstream os;
            os << R"({"exp":)" << timeSinceEpoch << "}";
            auto payloadLoad = os.str();

            auto verify = jwt::verify()
                    .allow_algorithm(jwt::algorithm::rs256(rsa2048PublicKey, rsa2048PrivateKey, "", ""));

            auto decoded_token = jwt::decode(token);
            verify.verify(decoded_token);

            auto decodeToken = decoded_token.get_payload();
            std::cout << "JWT token payload" << decoded_token.get_payload() << std::endl;
            BOOST_TEST(payloadLoad == decodeToken);

        } catch ( const std::exception& exception) {
            BOOST_FAIL(exception.what());
            std::cout << exception.what() << std::endl;
        } catch ( ... ) {
            BOOST_FAIL("Unknown exception...");
            std::cout << "Unknown..." << std::endl;
        }
    }

BOOST_AUTO_TEST_SUITE_END()
