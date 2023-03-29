//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/10.
//  Copyright 2019 Virtru Corporation
//

#define BOOST_TEST_MODULE test_asym_decoding_suite

#include "crypto/asym_decryption.cpp"
#include "bytes.h"
#include "crypto_utils.h"
#include "openssl_deleters.h"
#include "tdf_exception.h"

#include <boost/test/included/unit_test.hpp>

namespace vc = virtru::crypto;
using namespace std::string_literals;

std::string encryptMessage(const std::string& publicKey, const std::string& plainText);

BOOST_AUTO_TEST_SUITE(test_asym_decoding_suite)
    const auto rsa2048PublicKey =
            "-----BEGIN PUBLIC KEY-----\n"
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy6B+BSrO8pfeMXAvs4nE\n"
            "xIvKvhu3MqY51dmuuVNFADinouYBLiz5PyozeVO1mqf73aqyLOpwbZ0/eCafji4U\n"
            "FO/ZzhRpYFQrgvVVDZGaPtZfSKLwwhhbECp+JgQQqjJeqTWpoWb8UeJe9vwQGF/7\n"
            "xZgnE3ustWOOUpR1Kxf+AsJixdkhF9b9plyWynZsgen845MD1L8HmeEhWSLo7GXG\n"
            "tIrjOL8IIHjkCxhOl6PnzQ3cJ7JYFNwmFIPkW0ER2xYhJOZANf54jSc/0tYLJwwo\n"
            "OD62lTpVmZYbG+B+MQDRJLGSN2D/pGpzNe71zTVMOKTg0IZCZrW1VMNKDd6gyEgY\n"
            "0QIDAQAB\n"
            "-----END PUBLIC KEY-----"s;

    const auto rsa2048PrivateKey =
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDLoH4FKs7yl94x\n"
            "cC+zicTEi8q+G7cypjnV2a65U0UAOKei5gEuLPk/KjN5U7Wap/vdqrIs6nBtnT94\n"
            "Jp+OLhQU79nOFGlgVCuC9VUNkZo+1l9IovDCGFsQKn4mBBCqMl6pNamhZvxR4l72\n"
            "/BAYX/vFmCcTe6y1Y45SlHUrF/4CwmLF2SEX1v2mXJbKdmyB6fzjkwPUvweZ4SFZ\n"
            "IujsZca0iuM4vwggeOQLGE6Xo+fNDdwnslgU3CYUg+RbQRHbFiEk5kA1/niNJz/S\n"
            "1gsnDCg4PraVOlWZlhsb4H4xANEksZI3YP+kanM17vXNNUw4pODQhkJmtbVUw0oN\n"
            "3qDISBjRAgMBAAECggEATyL6lwuCDioTgmc1QrNiM3iYvLWMxzRu+bt1+jRwdpuO\n"
            "GvMEtmtoGrJN+vMbexWZ/xYd1PLv6snYJtvr2pfx2gk1PrAUHAnaNzUdbv6NUaqC\n"
            "sXoR030ftvKswB2IVHzq6Rwf5shde31cpuRjZPW4pZxyY1IHVx9v6owj1TGn2G39\n"
            "kO2GmKO9s88AvxFsM/xAIkmEPKO9KJLyc5qAATuzlHC37iCbQ9mA3tsvJsf2VVHG\n"
            "xld6PRFoQgJmlaoX91WSLvHhLlQNPIAszsuUkJYjTF8bQpJsnqxJJSQSyh9SJBbr\n"
            "+EH2Uf7lHt8Ej9HnCJ7F5mHeWK2eSV1GIcjiYFxJgQKBgQD0W3S70PdxG628iy4w\n"
            "WQA5chjzs5xtonHij4GX0l17MkaRMNZ/7yfS8ck3ZTvPZjQwbE5EGiTW61NSWPVz\n"
            "WKS8xnCl8N50FWVxxKtVNv9NOFGzmi6LHG3RUL76UknDlB9ZuKvCgYOp+LHjhNis\n"
            "DgHgtNCB5k5RFkDdYtgkbIs8WQKBgQDVVDqMQMyMkPzsZg6wqEZ+PxrA90NE86Ja\n"
            "w6FSHAaEjqBsqFuVEtBn/x2J9cR+TnH7vLHtdVJ75NYGTIFlXXWy4e0l/1vD5PUc\n"
            "w+0LP87m6kWVyhSfuIJ89YOS4l9ddNHStM2oM1AMqfglpxQCI4rps/ICu4Ecz8WC\n"
            "m+DVPLvROQKBgQDtlR5inkJ3jtnVP92g1GgLcowgJropPpBMIAt4eei6J5/E+x8T\n"
            "NIwb5Uomuh71AAIuMp/GR0UaUaOppSTBCabihG5yaUdgxozjmLydFeQUSHXnkjk+\n"
            "uF1t7nxBFlDx/8qbiZo2e4ZwdIVBGaExaE0bFbLFGg97d4+JsNlGUOLvwQKBgCPa\n"
            "10hRb8/EYq487QUmE0sOwilipazGIiiNLuUFDtdivXXlyhbBJcQE7esNIqxz9NZx\n"
            "vZoCmQ13xb0jSLBHyAt7y4cSZ1MCfWwLRiEY5WaMQ4vMfjDmKxBjl2ytnYewpb97\n"
            "YgF+NlsaijmR3lwJq0RiWS+6YhX8md684koUviCJAoGBAKDs5Hxb4TpzFAE3eD7B\n"
            "eTxMYhKtSwVLg9OGDxxxkg6m3bfuSOgSKbC17IxcEBwky54IlkJS9uqIIvwEokzP\n"
            "zgxp/lGe3KyjeOM4NOPVeMxYDPYb5+rYzrnnTX5yBhqZqOIkzaFAtALFUYNUagbB\n"
            "DCzGcDpkNVkPR58v1BvBs4zZ\n"
            "-----END PRIVATE KEY-----"s;

    const auto rsa4096PublicKey =
            "-----BEGIN PUBLIC KEY-----\n"
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmoWCH8tR9UiUN4QMLrZk\n"
            "1dpq+iBDCiDppYVUlaYIOCzREvBvBEyA4vkrDDOf4i0c4q5rAL8g3JfMjtjdTXyI\n"
            "KsmYpxFfsqhTkP2ONVi4ml3Ny5FScUQCeavW143aFkwCXVeG47hP7ihrgRqu6f0K\n"
            "4EFdRHlJI1dNIfvt3SkCocV3LKK94qeBpA3pQpBCey5ni5q3TvWS+TCF8YmO0FHW\n"
            "CSGc9uSosc2YT9jzuGGwSLDlKN0lTZBktlvaoeG2mboLmM12CTKnSbPqZwo+muUK\n"
            "etjtDnIkKWYKp46bVdmc29zVMcEc/A29jlh4/OtpnJz5l9jEAIRyJriwl6RwgWws\n"
            "6XC8zUCDVxN7QSjLgnxykau/eqI71+9YGPh2DpWnQodf9S0keklop/4vXbPuFqSu\n"
            "1xNY5JQkrUeeFQsWQQsEQPl5jPdJ7mR4p/MIOLSpZwBkBdpKk7W/ILFyRr8wMPTg\n"
            "2I6DouUHGxdJWq0IaaCdnpQ+NN9mzlz0nv+xFk1sulk8EMhVnAOjGmbVnZDT6dIl\n"
            "gyYTg09Cftr1dxdYZ8ioCkQdZ7IbrqDVhd62aLG31tHLSsgdZeQr57WFJj79Jvj0\n"
            "FuRvfHchmoBDDyR2zFgEhezchWD9QhgWTbg6jHWkxjjTeQsb2CmPGY9sYFqE+KB/\n"
            "z5PY2ofyevYje5ks4iz0G58CAwEAAQ==\n"
            "-----END PUBLIC KEY-----"s;

    const auto rsa4096PrivateKey =
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQCahYIfy1H1SJQ3\n"
            "hAwutmTV2mr6IEMKIOmlhVSVpgg4LNES8G8ETIDi+SsMM5/iLRzirmsAvyDcl8yO\n"
            "2N1NfIgqyZinEV+yqFOQ/Y41WLiaXc3LkVJxRAJ5q9bXjdoWTAJdV4bjuE/uKGuB\n"
            "Gq7p/QrgQV1EeUkjV00h++3dKQKhxXcsor3ip4GkDelCkEJ7LmeLmrdO9ZL5MIXx\n"
            "iY7QUdYJIZz25KixzZhP2PO4YbBIsOUo3SVNkGS2W9qh4baZuguYzXYJMqdJs+pn\n"
            "Cj6a5Qp62O0OciQpZgqnjptV2Zzb3NUxwRz8Db2OWHj862mcnPmX2MQAhHImuLCX\n"
            "pHCBbCzpcLzNQINXE3tBKMuCfHKRq796ojvX71gY+HYOladCh1/1LSR6SWin/i9d\n"
            "s+4WpK7XE1jklCStR54VCxZBCwRA+XmM90nuZHin8wg4tKlnAGQF2kqTtb8gsXJG\n"
            "vzAw9ODYjoOi5QcbF0larQhpoJ2elD4032bOXPSe/7EWTWy6WTwQyFWcA6MaZtWd\n"
            "kNPp0iWDJhODT0J+2vV3F1hnyKgKRB1nshuuoNWF3rZosbfW0ctKyB1l5CvntYUm\n"
            "Pv0m+PQW5G98dyGagEMPJHbMWASF7NyFYP1CGBZNuDqMdaTGONN5CxvYKY8Zj2xg\n"
            "WoT4oH/Pk9jah/J69iN7mSziLPQbnwIDAQABAoICADWrh53ZdfcXJXv+3mhfK7jn\n"
            "q16DVCWxdtXp8I4l5Bb24guM/VJl7CJp3xzW1YKunqjRYhMZT6WvB/rZskwWpAkQ\n"
            "ingE3dNlCdmDaCB5V20uhateJ191+tId8HpgJ860yeF35D82JnUXDvgBt51IKb3o\n"
            "lieRZOjkisLyCRVXCDX+Kz2SrReLjMjZmBpplt3IKWjg7Sh8vXbV9sAFQlhzBD+Z\n"
            "sDZFB57yRSP+u/Bf5eXpoz7FSQ6ex4xbbR3rEwxkBWEmhAf/0wETf6gYc9RDF5fB\n"
            "vtzUomDKs4qtSqDP+96V3mrwo0uczikh66wVbFJcZ4jpXnK7jhaK8bNKB1W8qABG\n"
            "3SHE9UMg07XD10psgiA3gCHVJSelyQr9/qJVXPIMhEP0iUHu3HvHDrhEPmof8yKJ\n"
            "6agxgUsbdq8Y7mDk2dSCZrVTeuqVJ7hkJBin6NzRIKS96dk2dY/Yqnuo/EBVZ2BG\n"
            "eDPB5dEP5FyOrd7ULplfPch0Fo7Gm8luqh8L/K7oXh0om69GUi905LofAX07vzL8\n"
            "B0RJ/eKH2zITfJqgxrb3Ly4dP4e5dV343S1/pURGvPP3hLDC2BXXh4pOlQU2xj31\n"
            "XFIIU7rAjyo8I6hlfmbyW3137ILR7xZkrH4B4SJPqLi02OVh0KAfCGOjN8JkSg+t\n"
            "OrrxwuiKEhUJYKZh+bE5AoIBAQDJ7iYAKkHouNV9ofgRRlOsPMgqurJPvA3WCKfq\n"
            "Sjs5Z0IwH4iF7QiJAlMHELUytdWhcrEsBHNZY95heXHEnVeAAEVk53Oze7pa5kcd\n"
            "vkJ6ySMBbbJChFy0+j8MBUWtBiSmqxerX2Bj36ytK/oGgZgIhLuyAjbQY0ioeUfX\n"
            "ZZagqqGPT2ShyyYQQV0WtcJOhAaiLLrEYwyHTdTlcirjKII7Hpt1cfnUAQvCLzWZ\n"
            "S/P0SVcDpKA/HvToQ5S39ENSAIY0ZLsc++thP7X95iLdiuwNQHdXG75/cWX3vJqe\n"
            "qAgRxPn+Jj3b9wVlT3YYlBX4bc1vkOSjyyFDYRItNb+Y+3gVAoIBAQDD5ZmWCIka\n"
            "tnhnjHucCCrFZZliaBHrrAEomDNrgO7zeuR8U0UNcf0lDTMg8Q68VJcWgmk389Gl\n"
            "a8rQjZ4rxhjJAVoUxZTFUWSge64t07scOMkzAbYAisea3p2HgqunIutDA7GEj3uR\n"
            "OB+TWg039UDWV5Pa48oWk4TCq5z0GiiC5oHIRTsVCYq+4Buum9ct1sklJf7Qdo66\n"
            "BZvMoT2LY4fsfthVS94EnFd+HzwJyAc2nBHKMzL8l/qfT4QH0AqZuHrisTrq5rns\n"
            "9OYnUd4njAGfnPTdW2HOrCqudEPjhnxOxFs/R6dAONtc+WzmNiUFQJRrWm+u8BJD\n"
            "CvAoox3TNV3jAoIBABjnsXIlxBlC6rnjByiCRwGgQYPboPBqnj4+tQ8VdrZ+wNAU\n"
            "o475DCtxyPG/IsoNWTrfXXCzX9KvmZbmFp0MVuVnoydt0Hxbj0F002Kcu7BPLG0Z\n"
            "rXm8v35muu3tnIlZj52qznGJgubuiGqXWPACfdDXJhsvYLlU9Xop8y1izzAju2dk\n"
            "gGHgH2Kz3RpW8o8ig3rvD133ZW0usUpXSWjY7y8BeGUE2K5ILr4VeoPctUr03LGL\n"
            "VWRTmhsncqk5jDAJ9oNxxQ4vF/nXlMeq4bP3VWPRBqcMufMX9l6WuW9GBDDE3Zx1\n"
            "9P0zO0wif8tKQGdyi3ruIPT+sayQxWAkF+xzX30CggEBAINyIZ95tL226I3axuqI\n"
            "1GJF7SkJ2dSAQvrBPeeJyUyZDo2ZtkDyVsEw3TjiZ1fZjtPsx7tioC7WaG2OSS7o\n"
            "KqNdg9tiRJQuLE4/Dz3yz599Pww5vq0Ych0p+Rv/gzyQArqh1NC1El38Abv29d2x\n"
            "dEMe2rhKlsSVUcTqMFPe5YYIM9d1FNLl5zJy4EBGk5lPgQKrPxMUKmsJ7mPdYZWR\n"
            "QJhg+LorQRto6JBZVwjdLnHnQUyjFDhHpkSVr2sqnqJNFi/cakNKdEFahsClf2Kb\n"
            "4E8Am5GYisWJ4s3Sd+dIy0pzGSMZ6lD+lbsKJpdGh4rBrZVnRn9k2Wwg/8rUwOOC\n"
            "8K8CggEBAK0Wmsqhu3SbptguFlxBIGJAYR9Jf+7SBhZrlRV0W0B7n/KnxP4BOcQ5\n"
            "FH+0cT1NURt2+M4rC3TJW/XOZ52m+wWRyvlEDp0UnhfRvb72xToqdvt1LkJxsDai\n"
            "aIpZn6ALebK7Y8WDtslqT2TFxVTlhRdWRooPWE/2/BoCOzYEEKQZD3OEYdcHIUXV\n"
            "x9uhbscBOb3RwnzAlYCjQf4oA+cArdRWVQvo6OcIxbMzexhGw69sEXbYDRZYqBbj\n"
            "wGcAAHSagQDoulTvJ5IhZz7JgZBu1bO5QKKxLoOPvDydzg0WYh5BrP1oMKxygr6u\n"
            "Z1CvwNOGi8HkK239QjNlZuhfaNR17bY=\n"
            "-----END PRIVATE KEY-----"s;

    const auto plainTextMessage = "Virtru!!"s;
    const auto base64Ciphertext =
            "eSxyWCxR/NXwM5zOMjc7YXdbieEkMFC6vlUXhJyw2SIVJgqfMwGNQI8lsu4dOrX5"
            "Tb6IHOOx1exN2ihNTKezyuWNyA4iKSNfP5ydIhSwynwLLKR+1xHYJ6pa13AkCLTn"
            "g2afd/146z58ZsGXfWF5M4Kh9fOXql6OAeGN2p6oAy70CgSDVwrX3vNobkv1SM"
            "Zl6uc8Y/Ew33cl/AuGZ87/PRjGyAW5g+08oLyCo7fQsYw3Agjf94BFpCxfs+QRhuIq"
            "NI4g6fbjAwS/Yw2E/9wYNfLAB8QRclatZVKhdh0FlzgMyO+5m5bnKmR6u3fm8sV"
            "faWcPSTzJ6oGz6fsaSqrqWg=="s;

    // This chipher test is for "Some text message" string
    const auto base64WrongCiphertext =
            "cjc9aOEtVdrmVP2JO8mgrYEdHg8DLg/sQ4fPjoLyg5QrCguJfw9ZZNFC9VzlrOxn"
            "wjGAT3LyntZHvcOFuIBEPrFH4MMvlSiisWtoxl7WVfQ//ZFnQBygsIgtWJMyZpSc"
            "Z7/6xiljHXI/zVeROimLio0LMEftSqpakG20SnHnZxYdtchbOkWmlPqqNOAyiuN4"
            "mIQM2aJY4IvH/LpWZr0nIPStj/mAuWHI+y75tF22f7R1TxJgdvVHE51ZZ3UWNmaR"
            "lS1/vbWgz88VjlKowFCCDfgCu5whoq9LMrYYIcvko/SMCft2M89j8Ybtd5y7FSs5"
            "gwHvQ6wej6wk1Puj2KlhZQ=="s;

    BOOST_AUTO_TEST_CASE(test_asym_decoding_rsa2048) {
        const auto cipherText = vc::base64Decode(base64Ciphertext);
        auto decoder = vc::AsymDecryption::create(rsa2048PrivateKey);

        std::vector<gsl::byte> outBuffer(decoder->getOutBufferSize());
        auto writeableBytes = vc::toWriteableBytes(outBuffer);
        decoder->decrypt(vc::toBytes(cipherText), writeableBytes);

        std::string decryptedMessage(reinterpret_cast<const char *>(&writeableBytes[0]), writeableBytes.size());
        BOOST_TEST(plainTextMessage == decryptedMessage);
        
        outBuffer.resize(0);
        writeableBytes = vc::toWriteableBytes(outBuffer);
        BOOST_CHECK_THROW(decoder->decrypt(vc::toBytes(cipherText), writeableBytes), virtru::Exception);
    }

    BOOST_AUTO_TEST_CASE(test_asym_decoding_fail_tests) {
        
        const auto cipherText = vc::base64Decode(base64WrongCiphertext);
        auto decoder = vc::AsymDecryption::create(rsa2048PrivateKey);
        
        std::vector<gsl::byte> outBuffer(decoder->getOutBufferSize());
        auto writeableBytes = vc::toWriteableBytes(outBuffer);
        decoder->decrypt(vc::toBytes(cipherText), writeableBytes);
        
        std::string decryptedMessage(reinterpret_cast<const char *>(&writeableBytes[0]), writeableBytes.size());
        BOOST_TEST(plainTextMessage != decryptedMessage); // should fail

        // wrongKey
        BOOST_CHECK_THROW(vc::AsymDecryption::create(rsa2048PublicKey), virtru::crypto::CryptoException);
    }

    BOOST_AUTO_TEST_CASE(test_asym_decoding_rsa4096) {
        
        const auto base64EncodeChiperText = encryptMessage(rsa4096PublicKey, plainTextMessage);
        std::cout << "Encrypted base64:" << base64EncodeChiperText << std::endl;
        
        const auto cipherText = vc::base64Decode(base64EncodeChiperText);
        auto decoder = vc::AsymDecryption::create(rsa4096PrivateKey);
        
        std::vector<gsl::byte> outBuffer(decoder->getOutBufferSize());
        auto writeableBytes = vc::toWriteableBytes(outBuffer);
        decoder->decrypt(vc::toBytes(cipherText), writeableBytes);
        
        std::string decryptedMessage(reinterpret_cast<const char *>(&writeableBytes[0]), writeableBytes.size());
        BOOST_TEST(plainTextMessage == decryptedMessage);
    }

BOOST_AUTO_TEST_SUITE_END()

std::string encryptMessage(const std::string& publicKey, const std::string& plainText) {
    
    using namespace virtru::crypto;
    
    BIO_free_ptr publicKeyBuffer { BIO_new_mem_buf(publicKey.data(), publicKey.size()) };
    RSA_free_ptr rsaPublicKey {PEM_read_bio_RSA_PUBKEY(publicKeyBuffer.get(), nullptr, nullptr, nullptr) };
    size_t rsaSize = RSA_size(rsaPublicKey.get());
    std::vector<gsl::byte> encryptedData(rsaSize);
    
    auto outSize = RSA_public_encrypt(plainText.size(),
                                      reinterpret_cast<const unsigned char*>(plainText.data()),
                                      toUchar(encryptedData.data()),
                                      rsaPublicKey.get(),
                                      RSA_PKCS1_OAEP_PADDING);
    
    if (-1 == outSize) {
        BOOST_FAIL("encryptMessage failed");
    }
    
    return base64Encode(toBytes(encryptedData));
    
}
