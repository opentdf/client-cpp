//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/10.
//  Copyright 2019 Virtru Corporation
//

#define BOOST_TEST_MODULE test_asym_encoding_suite

#define NOMINMAX
#include <limits>
#include "asym_encryption.h"
#include "bytes.h"
#include "crypto_utils.h"
#include "openssl_deleters.h"
#include "tdf_exception.h"

#include <boost/test/included/unit_test.hpp>

namespace vc = virtru::crypto;
using namespace std::string_literals;
std::string decryptMessage(const std::string& privateKey, const std::string& ciphertextBase64);

BOOST_AUTO_TEST_SUITE(test_asym_encoding_suite)

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

    const auto plainTextMessage = "Virtru!!"s;

    BOOST_AUTO_TEST_CASE(test_asym_encoding_rsa2048) {

        auto encoder = vc::AsymEncryption::create(rsa2048PublicKey);
        std::vector<gsl::byte> outBuffer(encoder->getOutBufferSize());
        auto writeableBytes = vc::toWriteableBytes(outBuffer);
        encoder->encrypt(vc::toBytes(plainTextMessage), writeableBytes);

        auto encryptedMsg = vc::base64Encode(writeableBytes);
        std::cout << "Encrypted message rsa2048: " << encryptedMsg << std::endl;
        const auto message = decryptMessage(rsa2048PrivateKey, encryptedMsg);
        BOOST_TEST(plainTextMessage == message);
    }

    BOOST_AUTO_TEST_CASE(test_asym_encoding_x509_cert) {
        auto encoder = vc::AsymEncryption::create(publicKeyX509);
        
        auto publicKeyAsPem = encoder->pemFormat();
        std::cout << "Public key as pem: " << publicKeyAsPem << std::endl;
        
        BOOST_TEST(publicKeyAsPem == publicKeyPem);
        
        std::vector<gsl::byte> outBuffer(encoder->getOutBufferSize());
        auto writeableBytes = vc::toWriteableBytes(outBuffer);

        auto symmetricKey = vc::symmetricKey<32>();
        auto hexSymmetricKey = vc::hex(symmetricKey);
        auto base64SymmetricKey = vc::base64Encode(symmetricKey);
        std::cout << "Encrypted message hex: " << hexSymmetricKey << std::endl;
        std::cout << "Encrypted message Base64: " << base64SymmetricKey << std::endl;

        encoder->encrypt(vc::toBytes(symmetricKey), writeableBytes);

        auto encryptedMsg = vc::base64Encode(writeableBytes);
        std::cout << "Encrypted message: " << encryptedMsg << std::endl;
        const auto message = decryptMessage(privateKeyPem, encryptedMsg);

        auto hexmessage = vc::hex(vc::toBytes(message));
        BOOST_TEST(hexSymmetricKey == hexmessage);
    }

    BOOST_AUTO_TEST_CASE(test_asym_encoding_rsa4096) {
        
        auto encoder = vc::AsymEncryption::create(rsa4096PublicKey);
        std::vector<gsl::byte> outBuffer(encoder->getOutBufferSize());
        auto writeableBytes = vc::toWriteableBytes(outBuffer);
        encoder->encrypt(vc::toBytes(plainTextMessage), writeableBytes);
        
        auto encryptedMsg = vc::base64Encode(writeableBytes);
        std::cout << "Encrypted message rsa4096: " << encryptedMsg << std::endl;
        const auto message = decryptMessage(rsa4096PrivateKey, encryptedMsg);
        BOOST_TEST(plainTextMessage == message);
        
        // wrongKey
        BOOST_CHECK_THROW(vc::AsymEncryption::create(rsa4096PrivateKey), vc::CryptoException);
    }

    BOOST_AUTO_TEST_CASE(test_asym_encoding_samll_output_buffer) {
        auto encoder = vc::AsymEncryption::create(rsa4096PublicKey);
        std::vector<gsl::byte> outBuffer(encoder->getOutBufferSize() - 1);
        auto writeableBytes = vc::toWriteableBytes(outBuffer);
        BOOST_CHECK_THROW(encoder->encrypt(vc::toBytes(plainTextMessage), writeableBytes), virtru::Exception);
        
        outBuffer.resize(0);
        writeableBytes = vc::toWriteableBytes(outBuffer);
        BOOST_CHECK_THROW(encoder->encrypt(vc::toBytes(plainTextMessage), writeableBytes), virtru::Exception);
    }

    BOOST_AUTO_TEST_CASE(test_asym_encoding_big_input_buffer) {
        auto encoder = vc::AsymEncryption::create(rsa4096PublicKey);
        std::vector<gsl::byte> outBuffer(encoder->getOutBufferSize());
        auto writeableBytes = vc::toWriteableBytes(outBuffer);
        
        // Increase the input buffer size(should be encoder->getOutBufferSize() - 42 to be valid)
        const std::string inBuffer(encoder->getOutBufferSize() - 41, 'a');
        BOOST_CHECK_THROW(encoder->encrypt(vc::toBytes(inBuffer), writeableBytes), virtru::Exception);
    }

BOOST_AUTO_TEST_SUITE_END()

std::string decryptMessage(const std::string& privateKey, const std::string& ciphertextBase64) {
    using namespace virtru;
    using namespace virtru::crypto;
    auto ciphertext = base64Decode(ciphertextBase64);
    auto encryptedData = toBytes(ciphertext);

    EVP_PKEY_free_ptr privateKeyPtr;
    BIO_free_ptr privateKeyBuffer { BIO_new_mem_buf(privateKey.data(), privateKey.size()) };

    if (!privateKeyBuffer) {
        ThrowOpensslException("Failed to allocate memory for private key.");
    }

    // Store the private key into RSA struct
    privateKeyPtr.reset(PEM_read_bio_PrivateKey(privateKeyBuffer.get(), nullptr, nullptr, nullptr));
    if (!privateKeyPtr) {
        ThrowOpensslException("Failed to create a private key.");
    }

    if (encryptedData.size() > std::numeric_limits<int>::max()) {
        ThrowException("Asymmetric decoding input buffer is too big");
    }

    size_t decryptBufSize{};
    EVP_PKEY_CTX_free_ptr evpPkeyCtxPtr { EVP_PKEY_CTX_new(privateKeyPtr.get(), NULL)};
    if (!evpPkeyCtxPtr) {
        ThrowOpensslException("Failed to create EVP_PKEY_CTX.");
    }

    auto ret = EVP_PKEY_decrypt_init(evpPkeyCtxPtr.get());
    if (ret != 1) {
        ThrowOpensslException("Failed to initialize decryption process.");
    }

    ret = EVP_PKEY_CTX_set_rsa_padding(evpPkeyCtxPtr.get(), RSA_PKCS1_OAEP_PADDING);
    if (ret <= 0) {
        ThrowOpensslException("Failed to create EVP_PKEY_CTX.");
    }

    if (EVP_PKEY_decrypt(evpPkeyCtxPtr.get(), nullptr, &decryptBufSize, toUchar(encryptedData.data()),
                         static_cast<int>(encryptedData.size())) <= 0) {
        ThrowOpensslException("Failed to calaculate the length of decrypt buffer EVP_PKEY_decrypt.");
    }

    std::vector<char> decryptedData(decryptBufSize);
    ret = EVP_PKEY_decrypt(evpPkeyCtxPtr.get(),
                           reinterpret_cast<std::uint8_t *>(decryptedData.data()),
                           &decryptBufSize,
                           toUchar(encryptedData.data()),
                           static_cast<int>(encryptedData.size()));
    if (ret <= 0) {
        ThrowOpensslException("Decryption failed using asymmetric decoding.");
    }
    decryptedData.resize(decryptBufSize);

    std::string plainText(decryptedData.begin(), decryptedData.end());
    return plainText;
}
