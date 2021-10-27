//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/22.
//  Copyright 2019 Virtru Corporation
//

#define BOOST_TEST_MODULE test_attribute_objects_cache_suite

#include "attribute_objects_cache.h"
#include "entity_object.h"
#include "tdf_exception.h"

#include <jwt/jwt.h>
#include <jwt/picojson.h>
#include <string>
#include <iostream>

#include <boost/test/included/unit_test.hpp>


BOOST_AUTO_TEST_SUITE(test_attribute_objects_cache_suite)

    using namespace virtru;
    using namespace std::string_literals;

    /// Constants
    static constexpr auto kAttribute = "attribute";
    static constexpr auto kDisplayName = "displayName";
    static constexpr auto kIsDefault = "isDefault";
    static constexpr auto kPubKey = "pubKey";
    static constexpr auto kKasURL = "kasUrl";


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

    const auto kDefaultAttribute = "https://example.com/attr/classification-deafult"s;
    const auto kDisplayNameValue = "classification"s;
    const auto kKasURLValue = "https://kas.example.com/"s;

    BOOST_AUTO_TEST_CASE(test_attribute_objects_cache_test)
    {
        auto entityObject = EntityObject{};

        // Build an array of attributes for creating jwt's
        std::vector<std::string> attributes = { "https://example.com/attr/classification1",
                                                "https://example.com/attr/classification2",
                                                "https://example.com/attr/classification3",
                                                "https://example.com/attr/classification4",
                                                "https://example.com/attr/classification5" };
        try {

            auto token = jwt::create()
                    .set_type("JWT")
                    .set_payload_claim(kAttribute, kDefaultAttribute)
                    .set_payload_claim(kDisplayName, kDisplayNameValue)
                    .set_payload_claim(kPubKey, std::string{rsa2048PublicKey})
                    .set_payload_claim(kKasURL, kKasURLValue)
                    .set_payload_claim(kIsDefault, picojson::value{true})
                    .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{60})
                    .sign(jwt::algorithm::rs256(rsa2048PublicKey, rsa2048PrivateKey));

            entityObject.setUserId("owner@example.com")
                    .setAliases("user1@example.com")
                    .setAttributeAsJwt(token)
                    .setPublicKey(rsa2048PublicKey)
                    .setCert("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ");

            for (auto& attribute : attributes) {
                token = jwt::create()
                        .set_type("JWT")
                        .set_payload_claim(kAttribute, attribute)
                        .set_payload_claim(kDisplayName, kDisplayNameValue)
                        .set_payload_claim(kPubKey, std::string{rsa2048PublicKey})
                        .set_payload_claim(kKasURL, kKasURLValue)
                        .set_payload_claim(kIsDefault, picojson::value{false})
                        .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{60})
                        .sign(jwt::algorithm::rs256(rsa2048PublicKey, rsa2048PrivateKey));
                entityObject.setAttributeAsJwt(token);
            }

        } catch ( const std::exception& exception) {
            BOOST_FAIL(exception.what());
            std::cout << exception.what() << std::endl;
        } catch ( ... ) {
            BOOST_FAIL("Unknown exception...");
            std::cout << "Unknown..." << std::endl;
        }

        AttributeObjectsCache attributeObjectsCache{entityObject};

        constexpr auto kSomeAttribute = "https://example.com/attr/classification20";
        attributeObjectsCache.addAttributeObject({kSomeAttribute, kDisplayNameValue, rsa2048PublicKey, kKasURLValue});


        BOOST_TEST(attributeObjectsCache.hasDefaultAttribute() == true);
        BOOST_TEST(attributeObjectsCache.hasAttributeObject(kDefaultAttribute) == true);
        BOOST_TEST(attributeObjectsCache.hasAttributeObject(kSomeAttribute) == true);
        BOOST_TEST(attributeObjectsCache.hasAttributeObject("https://api.virtru.com/attr/default/value/not-found") == false);

        for (auto& attribute : attributes) {
            BOOST_TEST(attributeObjectsCache.hasAttributeObject(attribute) == true);
        }

        auto defaultAttribute = attributeObjectsCache.getDefaultAttributeObject();
        BOOST_TEST(defaultAttribute.isDefault() == true);
        BOOST_TEST(defaultAttribute.getAttribute() == kDefaultAttribute);
        BOOST_TEST(defaultAttribute.getKasPublicKey() == rsa2048PublicKey);
        BOOST_TEST(defaultAttribute.getDisplayName() == kDisplayNameValue);
        BOOST_TEST(defaultAttribute.getKasBaseUrl() == kKasURLValue);


        auto someAttribute = attributeObjectsCache.getAttributeObject(kSomeAttribute);
        BOOST_TEST(someAttribute.isDefault() == false);
        BOOST_TEST(someAttribute.getAttribute() == kSomeAttribute);
        BOOST_TEST(someAttribute.getKasPublicKey() == rsa2048PublicKey);
        BOOST_TEST(someAttribute.getDisplayName() == kDisplayNameValue);
        BOOST_TEST(someAttribute.getKasBaseUrl() == kKasURLValue);

        auto result = attributeObjectsCache.deleteAttributeObject(kSomeAttribute);
        BOOST_TEST(result == true);

        result = attributeObjectsCache.deleteAttributeObject(kSomeAttribute);
        BOOST_TEST(result == false);

        result = attributeObjectsCache.hasAttributeObject(kSomeAttribute);
        BOOST_TEST(result == false);

        BOOST_CHECK_THROW(attributeObjectsCache.getAttributeObject(kSomeAttribute), virtru::Exception);

        // Remove default attribute.
        result = attributeObjectsCache.deleteAttributeObject(kDefaultAttribute);
        BOOST_TEST(result == true);

        BOOST_CHECK_THROW(attributeObjectsCache.getDefaultAttributeObject(), virtru::Exception);

        AttributeObjectsCache emptyAttributeObjectsCache{};
        BOOST_CHECK_THROW(emptyAttributeObjectsCache.getDefaultAttributeObject(), virtru::Exception);
        BOOST_TEST(attributeObjectsCache.hasDefaultAttribute() == false);

        result = emptyAttributeObjectsCache.hasAttributeObject(kSomeAttribute);
        BOOST_TEST(result == false);

        BOOST_CHECK_THROW(emptyAttributeObjectsCache.getAttributeObject(kDefaultAttribute), virtru::Exception);
    }


BOOST_AUTO_TEST_SUITE_END()