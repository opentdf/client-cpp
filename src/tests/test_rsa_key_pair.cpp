//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/07.
//  Copyright 2019 Virtru Corporation
//

#define BOOST_TEST_MODULE test_rsa_key_pair

#include "rsa_key_pair.h"
#include "crypto_utils.h"
#include "sdk_constants.h"

#include <string>
#include <iostream>

#include <boost/test/included/unit_test.hpp>
#include <openssl/bio.h>
#include <openssl/pem.h>

using namespace std::string_literals;
BOOST_AUTO_TEST_SUITE(test_rsa_key_pair_suite)

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

namespace vc = virtru::crypto;
struct BioDeleter { void operator()(BIO* bio) {::BIO_free(bio);} };
struct RsaDeleter {	void operator()(RSA* rsa) {	::RSA_free(rsa); }	};

BOOST_AUTO_TEST_CASE(rsa_key_pair_2048)
{
    auto keyPairOf2048 = vc::RsaKeyPair::Generate(2048);
    auto privateKey = keyPairOf2048->PrivateKeyInPEMFormat();
    auto publicKey = keyPairOf2048->PublicKeyInPEMFormat();

    std::unique_ptr<BIO, BioDeleter> privateKeyBuffer { BIO_new_mem_buf(privateKey.data(), privateKey.size()) };
    std::unique_ptr<RSA, RsaDeleter> privateRSA { PEM_read_bio_RSAPrivateKey(privateKeyBuffer.get(),
            nullptr, nullptr, nullptr) };

    std::unique_ptr<BIO, BioDeleter> publicKeyBuffer { BIO_new_mem_buf(privateKey.data(), privateKey.size()) };
    std::unique_ptr<RSA, RsaDeleter> publicRSA { PEM_read_bio_RSAPrivateKey(publicKeyBuffer.get(), nullptr,
            nullptr, nullptr) };

    BOOST_TEST(RSA_size(privateRSA.get()) == 256, "Checking RSA private key length - key size 256 bytes");
    BOOST_TEST(RSA_size(publicRSA.get()) == 256, "Checking RSA public key length - key size 256 bytes");
}

BOOST_AUTO_TEST_CASE(rsa_key_pair_4096)
{
    auto keyPairOf4096 = vc::RsaKeyPair::Generate(4096);
    auto privateKey = keyPairOf4096->PrivateKeyInPEMFormat();
    auto publicKey = keyPairOf4096->PublicKeyInPEMFormat();

    std::unique_ptr<BIO, BioDeleter> privateKeyBuffer { BIO_new_mem_buf(privateKey.data(), privateKey.size()) };
    std::unique_ptr<RSA, RsaDeleter> privateRSA { PEM_read_bio_RSAPrivateKey(privateKeyBuffer.get(),
            nullptr, nullptr, nullptr) };

    std::unique_ptr<BIO, BioDeleter> publicKeyBuffer { BIO_new_mem_buf(privateKey.data(), privateKey.size()) };
    std::unique_ptr<RSA, RsaDeleter> publicRSA { PEM_read_bio_RSAPrivateKey(publicKeyBuffer.get(),
            nullptr, nullptr, nullptr) };

    BOOST_TEST(RSA_size(privateRSA.get()) == 512, "Checking RSA private key length - key size 512 bytes");
    BOOST_TEST(RSA_size(publicRSA.get()) == 512, "Checking RSA public key length - key size 512 bytes");
}

BOOST_AUTO_TEST_CASE(rsa_key_pair_negative_test)
{
    try {
        auto desginedToFailkeyPair = vc::RsaKeyPair::Generate(-1);
        auto privateKey = desginedToFailkeyPair->PrivateKeyInPEMFormat();
        auto publicKey = desginedToFailkeyPair->PublicKeyInPEMFormat();
        BOOST_FAIL("We should not get here" );
    } catch ( const vc::CryptoException& exception) {
        BOOST_TEST_MESSAGE("Expect crypto exception");
        std :: cout << exception.what() << std::endl;
    } catch ( ... ) {
        BOOST_FAIL("Crypto exception should be thrown" );
        std :: cout << "...\n";
    }
}

BOOST_AUTO_TEST_CASE(rsa_test_sign_and_verify) {
        using namespace virtru::crypto;
        try {
            const std::string kPlainText = "Virtru";
            auto digest = calculateSHA256(toBytes(kPlainText));
            auto signature = RsaKeyPair::ComputeRSASig( toBytes(digest), rsa4096PrivateKey);
            auto result = RsaKeyPair::VerifyERSASignature(toBytes(digest), toBytes(signature), rsa4096PublicKey);
            BOOST_TEST(result);
        } catch (const vc::CryptoException &exception) {
            BOOST_TEST_MESSAGE("Expect crypto exception");
            std::cout << exception.what() << std::endl;
        } catch (...) {
            BOOST_FAIL("Crypto exception should be thrown");
            std::cout << "...\n";
        }
    }

BOOST_AUTO_TEST_SUITE_END()