//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/25.
//  Copyright 2019 Virtru Corporation
//

#define BOOST_TEST_MODULE test_entity_object_suite

#include "entity_object.h"

#include <boost/test/included/unit_test.hpp>


BOOST_AUTO_TEST_SUITE(test_entity_object_suite)

    using namespace virtru;
    BOOST_AUTO_TEST_CASE(test_entity_object) {
        constexpr auto entityObjectJsonStr = "{\n"
                                             "    \"aliases\": [\"sreddy@trusteddataformat.org\", \"sreddy@trusteddataformat.net\"], \n"
                                             "    \"attributes\": [\n"
                                             "        {\n"
                                             "            \"jwt\": \"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1cmwiOiJodHRwczovL2FhLnZpcnRydS5jb20vYXR0ci91bmlxdWUtaWRlbnRpZmllci92YWx1ZS9mZTEzZjBmYS0xNmU1LTQ3ZDYtODdjYy1hOTI1MzJhYzcxYzQiLCJuYW1lIjoiZmUxM2YwZmEtMTZlNS00N2Q2LTg3Y2MtYTkyNTMyYWM3MWM0IiwiaWF0IjoxNTUzNDg1MjQ3LCJleHAiOjE1NTM1NzE2NDd9.qg8BYLJ6ZKu6e641_NLfjlghDwWexEr_YUCadUyPX-B1tonWIJUjGddhx2cz5H8Ldxpj0AurilCz2xAIcRItwm9-0M3RlNUAZ7l5wYahRnSWijwV4lL7Yvm_HwMYgrrVNvcUwj5cqpMREHfCDScS-lSb89zhq76dypVmkgmhZe3t9lD1fTSJKCJylc7X9AzbWzLc0fDQH702yU__ZVOVkBwTO2jJ4ovBDPB0w9LgCEZ-9pzvdUiTdYuhZ2PzQBTNHlK1xxQQCu148uuiTw8Fk_bs7efuGgUU7zfrKR2Lvgw5QLDpavL11HnXIKZihxzJbcrjBdKQCK0V7v3i7F2CkA\"\n"
                                             "        }, \n"
                                             "        {\n"
                                             "            \"jwt\": \"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1cmwiOiJodHRwczovL2FhLnZpcnRydS5jb20vYXR0ci9wcmltYXJ5LW9yZ2FuaXphdGlvbi92YWx1ZS9mZTEzZjBmYS0xNmU1LTQ3ZDYtODdjYy1hOTI1MzJhYzcxYzQiLCJuYW1lIjoiZmUxM2YwZmEtMTZlNS00N2Q2LTg3Y2MtYTkyNTMyYWM3MWM0IiwiaWF0IjoxNTUzNDg1MjQ3LCJleHAiOjE1NTM1NzE2NDd9.TBO2RbLIESO5h3n8Cop4DVYJNhI46nfaAIuzUuTJ73v5j0myplcj3amNyW_PPRxSauMhG5gwhkSrYHgnO-f423a7YnGW1SmfqmpEFd8s5j1yGRIytJsuaVD0B5nfrjSkS4Bu5lV8J2pYmnanZkr_Mo6oj2_IhITk0lVBTgri-PTUfGKNCFfCI3bpFH2UwbvNzJD6wniW5C9rOG7oBMSbDTOK2HJK_3mf1DifzoH0iQY2r5fyJzomtYDd2Z4BGtPnWpU6wAF3rcfOYqYDW1KA74PsPZm2kaqC7Icq1PvqFglX3QwpmvQqpEvzWSNS3nNFui5yjupkHSlXfU24CEn3EA\"\n"
                                             "        }, \n"
                                             "        {\n"
                                             "            \"jwt\": \"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1cmwiOiJodHRwczovL2FhLnZpcnRydS5jb20vYXR0ci9zdXBlci1hZG1pbi92YWx1ZS90cnVlIiwibmFtZSI6dHJ1ZSwiaWF0IjoxNTUzNDg1MjQ3LCJleHAiOjE1NTM1NzE2NDd9.pkvAvRxU3pcqTCvUCuJtCwEg8UnXkLGKUgdH7aBnHWqCix_CXt_OqJ5T-b58xlszelyvcdmvTQxyg1_aHXOKg5wDQQaA6Ur3NsbYr3oskrPI8dE8gIK326NPpqrjrpBGGXkPoJHkXwGO5GfqtoNpuFWd8Y5UDLmH1QKegsBJQAVoV6JpWGvPyP_apAL8cNPNiTHuAL2RyE17ArhziHu6Ujaq_faJaC8sghSejGjW6SpdWiSF9Kw0rV4dZWjRsRu9qbWf3grMIMqEoP-3mSlpxhpDPWTS0hRaCnSvpneQynFvhbKMA2XA0z29Z9i6JueQisrjKVJ1PiaYvZIWNzz3OA\"\n"
                                             "        }\n"
                                             "    ],\n"
                                             "     \n"
                                             "    \"cert\": \"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJzcmVkZHlAdmlydHJ1ZGVwbG95LnVzIiwiYXR0cmlidXRlcyI6W3siand0IjoiZXlKaGJHY2lPaUpTVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SjFjbXdpT2lKb2RIUndjem92TDJGaExuWnBjblJ5ZFM1amIyMHZZWFIwY2k5MWJtbHhkV1V0YVdSbGJuUnBabWxsY2k5MllXeDFaUzltWlRFelpqQm1ZUzB4Tm1VMUxUUTNaRFl0T0Rkall5MWhPVEkxTXpKaFl6Y3hZelFpTENKdVlXMWxJam9pWm1VeE0yWXdabUV0TVRabE5TMDBOMlEyTFRnM1kyTXRZVGt5TlRNeVlXTTNNV00wSWl3aWFXRjBJam94TlRVek5EZzFNalEzTENKbGVIQWlPakUxTlRNMU56RTJORGQ5LnFnOEJZTEo2Wkt1NmU2NDFfTkxmamxnaER3V2V4RXJfWVVDYWRVeVBYLUIxdG9uV0lKVWpHZGRoeDJjejVIOExkeHBqMEF1cmlsQ3oyeEFJY1JJdHdtOS0wTTNSbE5VQVo3bDV3WWFoUm5TV2lqd1Y0bEw3WXZtX0h3TVlncnJWTnZjVXdqNWNxcE1SRUhmQ0RTY1MtbFNiODl6aHE3NmR5cFZta2dtaFplM3Q5bEQxZlRTSktDSnlsYzdYOUF6Yld6TGMwZkRRSDcwMnlVX19aVk9Wa0J3VE8yako0b3ZCRFBCMHc5TGdDRVotOXB6dmRVaVRkWXVoWjJQelFCVE5IbEsxeHhRUUN1MTQ4dXVpVHc4RmtfYnM3ZWZ1R2dVVTd6ZnJLUjJMdmd3NVFMRHBhdkwxMUhuWElLWmloeHpKYmNyakJkS1FDSzBWN3YzaTdGMkNrQSJ9LHsiand0IjoiZXlKaGJHY2lPaUpTVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SjFjbXdpT2lKb2RIUndjem92TDJGaExuWnBjblJ5ZFM1amIyMHZZWFIwY2k5d2NtbHRZWEo1TFc5eVoyRnVhWHBoZEdsdmJpOTJZV3gxWlM5bVpURXpaakJtWVMweE5tVTFMVFEzWkRZdE9EZGpZeTFoT1RJMU16SmhZemN4WXpRaUxDSnVZVzFsSWpvaVptVXhNMll3Wm1FdE1UWmxOUzAwTjJRMkxUZzNZMk10WVRreU5UTXlZV00zTVdNMElpd2lhV0YwSWpveE5UVXpORGcxTWpRM0xDSmxlSEFpT2pFMU5UTTFOekUyTkRkOS5UQk8yUmJMSUVTTzVoM244Q29wNERWWUpOaEk0Nm5mYUFJdXpVdVRKNzN2NWowbXlwbGNqM2FtTnlXX1BQUnhTYXVNaEc1Z3doa1NyWUhnbk8tZjQyM2E3WW5HVzFTbWZxbXBFRmQ4czVqMXlHUkl5dEpzdWFWRDBCNW5mcmpTa1M0QnU1bFY4SjJwWW1uYW5aa3JfTW82b2oyX0loSVRrMGxWQlRncmktUFRVZkdLTkNGZkNJM2JwRkgyVXdidk56SkQ2d25pVzVDOXJPRzdvQk1TYkRUT0sySEpLXzNtZjFEaWZ6b0gwaVFZMnI1ZnlKem9tdFlEZDJaNEJHdFBuV3BVNndBRjNyY2ZPWXFZRFcxS0E3NFBzUFptMmthcUM3SWNxMVB2cUZnbFgzUXdwbXZRcXBFdnpXU05TM25ORnVpNXlqdXBrSFNsWGZVMjRDRW4zRUEifSx7Imp3dCI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUoxY213aU9pSm9kSFJ3Y3pvdkwyRmhMblpwY25SeWRTNWpiMjB2WVhSMGNpOXpkWEJsY2kxaFpHMXBiaTkyWVd4MVpTOTBjblZsSWl3aWJtRnRaU0k2ZEhKMVpTd2lhV0YwSWpveE5UVXpORGcxTWpRM0xDSmxlSEFpT2pFMU5UTTFOekUyTkRkOS5wa3ZBdlJ4VTNwY3FUQ3ZVQ3VKdEN3RWc4VW5Ya0xHS1VnZEg3YUJuSFdxQ2l4X0NYdF9PcUo1VC1iNTh4bHN6ZWx5dmNkbXZUUXh5ZzFfYUhYT0tnNXdEUVFhQTZVcjNOc2JZcjNvc2tyUEk4ZEU4Z0lLMzI2TlBwcXJqcnBCR0dYa1BvSkhrWHdHTzVHZnF0b05wdUZXZDhZNVVETG1IMVFLZWdzQkpRQVZvVjZKcFdHdlB5UF9hcEFMOGNOUE5pVEh1QUwyUnlFMTdBcmh6aUh1NlVqYXFfZmFKYUM4c2doU2VqR2pXNlNwZFdpU0Y5S3cwclY0ZFpXalJzUnU5cWJXZjNnck1JTXFFb1AtM21TbHB4aHBEUFdUUzBoUmFDblN2cG5lUXluRnZoYktNQTJYQTB6MjlaOWk2SnVlUWlzcmpLVkoxUGlhWXZaSVdOenozT0EifV0sInB1YmxpY0tleSI6Ii0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tXG5NSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXVPMG54aEdDeXVFYkhPcU5YaldJXG4yZGZ1TkM5ano2SjlaS2IzZHZvc1pMdGlybzMyK2pnZWV1ZGNPMC9sMVArUnpHa09SVUd1YnJrTi9vVVd0QzlsXG5ESmdxM1QwNXBRSlVjZy8rc2J5TDFHdlVuVTBpSmZWazl6ejV3M2NEQkUvSTk5ckNHc0lmRzJtK3VuS0tKbjIyXG53ZC9aT3FRRE93Wk42b0RrQjdaV1FKZTBRQlF1YjBsSmpUaG9nclBWaVhJSnFSZ1RvSCt0c2pVWCtodGtwOFFBXG52dmt3MDlYYzFIWjZraFpWZGZZZjdCbTBZSTBPVkNNYko3N0JWc01HMGNDc0QvOGgzLzI2RjdvcTl1aWFlVG54XG5zWkJzemZCWEpHcFVtNDBuYWFRSi80Q0lxMjBRVGFkclhMTXAxQ1JNblI1VGNlTHZ2L0twR2xRR1hiNFY0elJmXG5xUUlEQVFBQlxuLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tIiwiYWxpYXNlcyI6W10sImlhdCI6MTU1MzQ4NTI0NywiZXhwIjoxNTUzNTcxNjQ3fQ.mh1ub1kS9WryrLGj3ONFmk6EGl6rPE29VJU21O3IX4EslCkxmIMVVjpFf8s83uFkyy7c2w5Re6NJsln9FHgLTV7RKqdj71U6tE7onh6l8_ZBNPCdetrCcrMCFac65k67_Lz5XM4BVPyCvNuoe-gY8FkeqyimQzkL6Q52HNG2FpslDrgcx50HiCC_aX638UyyB3W4n7J4uF8LrLzsNqyXb2xQw9BVVBJ9-XmXUgOmFaMMG5wJyxFETpP9yR3YBCwiZw911tc5CC738ho4IufdX98HBPqECMIkoL4ZJmfVw4N7YlbaJDU5WZa2rqCpgmvn_B4Zlv1QnVf41fj4EOifyg\",\n"
                                             "\n"
                                             "    \"publicKey\": \"-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuO0nxhGCyuEbHOqNXjWI\\n2dfuNC9jz6J9ZKb3dvosZLtiro32+jgeeudcO0/l1P+RzGkORUGubrkN/oUWtC9l\\nDJgq3T05pQJUcg/+sbyL1GvUnU0iJfVk9zz5w3cDBE/I99rCGsIfG2m+unKKJn22\\nwd/ZOqQDOwZN6oDkB7ZWQJe0QBQub0lJjThogrPViXIJqRgToH+tsjUX+htkp8QA\\nvvkw09Xc1HZ6khZVdfYf7Bm0YI0OVCMbJ77BVsMG0cCsD/8h3/26F7oq9uiaeTnx\\nsZBszfBXJGpUm40naaQJ/4CIq20QTadrXLMp1CRMnR5TceLvv/KpGlQGXb4V4zRf\\nqQIDAQAB\\n-----END PUBLIC KEY-----\", \n"
                                             "    \n"
                                             "    \"signerPublicKey\": \"-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuO0nxhGCyuEbHOqNXjWI\\n2dfuNC9jz6J9ZKb3dvosZLtiro32+jgeeudcO0/l1P+RzGkORUGubrkN/oUWtC9l\\nDJgq3T05pQJUcg/+sbyL1GvUnU0iJfVk9zz5w3cDBE/I99rCGsIfG2m+unKKJn22\\nwd/ZOqQDOwZN6oDkB7ZWQJe0QBQub0lJjThogrPViXIJqRgToH+tsjUX+htkp8QA\\nvvkw09Xc1HZ6khZVdfYf7Bm0YI0OVCMbJ77BVsMG0cCsD/8h3/26F7oq9uiaeTnx\\nsZBszfBXJGpUm40naaQJ/4CIq20QTadrXLMp1CRMnR5TceLvv/KpGlQGXb4V4zRf\\nqQIDAQAB\\n-----END PUBLIC KEY-----\", \n"
                                             "    \n"
                                             "    \"userId\": \"sreddy@virtrudeploy.us\"\n"
                                             "}";

        constexpr auto userId = "sreddy@virtrudeploy.us";
        constexpr auto alias1 = "sreddy@trusteddataformat.org";
        constexpr auto alias2 = "sreddy@trusteddataformat.net";
        constexpr auto publicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuO0nxhGCyuEbHOqNXjWI\n2dfuNC9jz6J9ZKb3dvosZLtiro32+jgeeudcO0/l1P+RzGkORUGubrkN/oUWtC9l\nDJgq3T05pQJUcg/+sbyL1GvUnU0iJfVk9zz5w3cDBE/I99rCGsIfG2m+unKKJn22\nwd/ZOqQDOwZN6oDkB7ZWQJe0QBQub0lJjThogrPViXIJqRgToH+tsjUX+htkp8QA\nvvkw09Xc1HZ6khZVdfYf7Bm0YI0OVCMbJ77BVsMG0cCsD/8h3/26F7oq9uiaeTnx\nsZBszfBXJGpUm40naaQJ/4CIq20QTadrXLMp1CRMnR5TceLvv/KpGlQGXb4V4zRf\nqQIDAQAB\n-----END PUBLIC KEY-----";
        constexpr auto signerPublicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuO0nxhGCyuEbHOqNXjWI\n2dfuNC9jz6J9ZKb3dvosZLtiro32+jgeeudcO0/l1P+RzGkORUGubrkN/oUWtC9l\nDJgq3T05pQJUcg/+sbyL1GvUnU0iJfVk9zz5w3cDBE/I99rCGsIfG2m+unKKJn22\nwd/ZOqQDOwZN6oDkB7ZWQJe0QBQub0lJjThogrPViXIJqRgToH+tsjUX+htkp8QA\nvvkw09Xc1HZ6khZVdfYf7Bm0YI0OVCMbJ77BVsMG0cCsD/8h3/26F7oq9uiaeTnx\nsZBszfBXJGpUm40naaQJ/4CIq20QTadrXLMp1CRMnR5TceLvv/KpGlQGXb4V4zRf\nqQIDAQAB\n-----END PUBLIC KEY-----";
        constexpr auto cert = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJzcmVkZHlAdmlydHJ1ZGVwbG95LnVzIiwiYXR0cmlidXRlcyI6W3siand0IjoiZXlKaGJHY2lPaUpTVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SjFjbXdpT2lKb2RIUndjem92TDJGaExuWnBjblJ5ZFM1amIyMHZZWFIwY2k5MWJtbHhkV1V0YVdSbGJuUnBabWxsY2k5MllXeDFaUzltWlRFelpqQm1ZUzB4Tm1VMUxUUTNaRFl0T0Rkall5MWhPVEkxTXpKaFl6Y3hZelFpTENKdVlXMWxJam9pWm1VeE0yWXdabUV0TVRabE5TMDBOMlEyTFRnM1kyTXRZVGt5TlRNeVlXTTNNV00wSWl3aWFXRjBJam94TlRVek5EZzFNalEzTENKbGVIQWlPakUxTlRNMU56RTJORGQ5LnFnOEJZTEo2Wkt1NmU2NDFfTkxmamxnaER3V2V4RXJfWVVDYWRVeVBYLUIxdG9uV0lKVWpHZGRoeDJjejVIOExkeHBqMEF1cmlsQ3oyeEFJY1JJdHdtOS0wTTNSbE5VQVo3bDV3WWFoUm5TV2lqd1Y0bEw3WXZtX0h3TVlncnJWTnZjVXdqNWNxcE1SRUhmQ0RTY1MtbFNiODl6aHE3NmR5cFZta2dtaFplM3Q5bEQxZlRTSktDSnlsYzdYOUF6Yld6TGMwZkRRSDcwMnlVX19aVk9Wa0J3VE8yako0b3ZCRFBCMHc5TGdDRVotOXB6dmRVaVRkWXVoWjJQelFCVE5IbEsxeHhRUUN1MTQ4dXVpVHc4RmtfYnM3ZWZ1R2dVVTd6ZnJLUjJMdmd3NVFMRHBhdkwxMUhuWElLWmloeHpKYmNyakJkS1FDSzBWN3YzaTdGMkNrQSJ9LHsiand0IjoiZXlKaGJHY2lPaUpTVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SjFjbXdpT2lKb2RIUndjem92TDJGaExuWnBjblJ5ZFM1amIyMHZZWFIwY2k5d2NtbHRZWEo1TFc5eVoyRnVhWHBoZEdsdmJpOTJZV3gxWlM5bVpURXpaakJtWVMweE5tVTFMVFEzWkRZdE9EZGpZeTFoT1RJMU16SmhZemN4WXpRaUxDSnVZVzFsSWpvaVptVXhNMll3Wm1FdE1UWmxOUzAwTjJRMkxUZzNZMk10WVRreU5UTXlZV00zTVdNMElpd2lhV0YwSWpveE5UVXpORGcxTWpRM0xDSmxlSEFpT2pFMU5UTTFOekUyTkRkOS5UQk8yUmJMSUVTTzVoM244Q29wNERWWUpOaEk0Nm5mYUFJdXpVdVRKNzN2NWowbXlwbGNqM2FtTnlXX1BQUnhTYXVNaEc1Z3doa1NyWUhnbk8tZjQyM2E3WW5HVzFTbWZxbXBFRmQ4czVqMXlHUkl5dEpzdWFWRDBCNW5mcmpTa1M0QnU1bFY4SjJwWW1uYW5aa3JfTW82b2oyX0loSVRrMGxWQlRncmktUFRVZkdLTkNGZkNJM2JwRkgyVXdidk56SkQ2d25pVzVDOXJPRzdvQk1TYkRUT0sySEpLXzNtZjFEaWZ6b0gwaVFZMnI1ZnlKem9tdFlEZDJaNEJHdFBuV3BVNndBRjNyY2ZPWXFZRFcxS0E3NFBzUFptMmthcUM3SWNxMVB2cUZnbFgzUXdwbXZRcXBFdnpXU05TM25ORnVpNXlqdXBrSFNsWGZVMjRDRW4zRUEifSx7Imp3dCI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUoxY213aU9pSm9kSFJ3Y3pvdkwyRmhMblpwY25SeWRTNWpiMjB2WVhSMGNpOXpkWEJsY2kxaFpHMXBiaTkyWVd4MVpTOTBjblZsSWl3aWJtRnRaU0k2ZEhKMVpTd2lhV0YwSWpveE5UVXpORGcxTWpRM0xDSmxlSEFpT2pFMU5UTTFOekUyTkRkOS5wa3ZBdlJ4VTNwY3FUQ3ZVQ3VKdEN3RWc4VW5Ya0xHS1VnZEg3YUJuSFdxQ2l4X0NYdF9PcUo1VC1iNTh4bHN6ZWx5dmNkbXZUUXh5ZzFfYUhYT0tnNXdEUVFhQTZVcjNOc2JZcjNvc2tyUEk4ZEU4Z0lLMzI2TlBwcXJqcnBCR0dYa1BvSkhrWHdHTzVHZnF0b05wdUZXZDhZNVVETG1IMVFLZWdzQkpRQVZvVjZKcFdHdlB5UF9hcEFMOGNOUE5pVEh1QUwyUnlFMTdBcmh6aUh1NlVqYXFfZmFKYUM4c2doU2VqR2pXNlNwZFdpU0Y5S3cwclY0ZFpXalJzUnU5cWJXZjNnck1JTXFFb1AtM21TbHB4aHBEUFdUUzBoUmFDblN2cG5lUXluRnZoYktNQTJYQTB6MjlaOWk2SnVlUWlzcmpLVkoxUGlhWXZaSVdOenozT0EifV0sInB1YmxpY0tleSI6Ii0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tXG5NSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXVPMG54aEdDeXVFYkhPcU5YaldJXG4yZGZ1TkM5ano2SjlaS2IzZHZvc1pMdGlybzMyK2pnZWV1ZGNPMC9sMVArUnpHa09SVUd1YnJrTi9vVVd0QzlsXG5ESmdxM1QwNXBRSlVjZy8rc2J5TDFHdlVuVTBpSmZWazl6ejV3M2NEQkUvSTk5ckNHc0lmRzJtK3VuS0tKbjIyXG53ZC9aT3FRRE93Wk42b0RrQjdaV1FKZTBRQlF1YjBsSmpUaG9nclBWaVhJSnFSZ1RvSCt0c2pVWCtodGtwOFFBXG52dmt3MDlYYzFIWjZraFpWZGZZZjdCbTBZSTBPVkNNYko3N0JWc01HMGNDc0QvOGgzLzI2RjdvcTl1aWFlVG54XG5zWkJzemZCWEpHcFVtNDBuYWFRSi80Q0lxMjBRVGFkclhMTXAxQ1JNblI1VGNlTHZ2L0twR2xRR1hiNFY0elJmXG5xUUlEQVFBQlxuLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tIiwiYWxpYXNlcyI6W10sImlhdCI6MTU1MzQ4NTI0NywiZXhwIjoxNTUzNTcxNjQ3fQ.mh1ub1kS9WryrLGj3ONFmk6EGl6rPE29VJU21O3IX4EslCkxmIMVVjpFf8s83uFkyy7c2w5Re6NJsln9FHgLTV7RKqdj71U6tE7onh6l8_ZBNPCdetrCcrMCFac65k67_Lz5XM4BVPyCvNuoe-gY8FkeqyimQzkL6Q52HNG2FpslDrgcx50HiCC_aX638UyyB3W4n7J4uF8LrLzsNqyXb2xQw9BVVBJ9-XmXUgOmFaMMG5wJyxFETpP9yR3YBCwiZw911tc5CC738ho4IufdX98HBPqECMIkoL4ZJmfVw4N7YlbaJDU5WZa2rqCpgmvn_B4Zlv1QnVf41fj4EOifyg";
        constexpr auto jwt1 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1cmwiOiJodHRwczovL2FhLnZpcnRydS5jb20vYXR0ci91bmlxdWUtaWRlbnRpZmllci92YWx1ZS9mZTEzZjBmYS0xNmU1LTQ3ZDYtODdjYy1hOTI1MzJhYzcxYzQiLCJuYW1lIjoiZmUxM2YwZmEtMTZlNS00N2Q2LTg3Y2MtYTkyNTMyYWM3MWM0IiwiaWF0IjoxNTUzNDg1MjQ3LCJleHAiOjE1NTM1NzE2NDd9.qg8BYLJ6ZKu6e641_NLfjlghDwWexEr_YUCadUyPX-B1tonWIJUjGddhx2cz5H8Ldxpj0AurilCz2xAIcRItwm9-0M3RlNUAZ7l5wYahRnSWijwV4lL7Yvm_HwMYgrrVNvcUwj5cqpMREHfCDScS-lSb89zhq76dypVmkgmhZe3t9lD1fTSJKCJylc7X9AzbWzLc0fDQH702yU__ZVOVkBwTO2jJ4ovBDPB0w9LgCEZ-9pzvdUiTdYuhZ2PzQBTNHlK1xxQQCu148uuiTw8Fk_bs7efuGgUU7zfrKR2Lvgw5QLDpavL11HnXIKZihxzJbcrjBdKQCK0V7v3i7F2CkA";
        constexpr auto jwt2 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1cmwiOiJodHRwczovL2FhLnZpcnRydS5jb20vYXR0ci9wcmltYXJ5LW9yZ2FuaXphdGlvbi92YWx1ZS9mZTEzZjBmYS0xNmU1LTQ3ZDYtODdjYy1hOTI1MzJhYzcxYzQiLCJuYW1lIjoiZmUxM2YwZmEtMTZlNS00N2Q2LTg3Y2MtYTkyNTMyYWM3MWM0IiwiaWF0IjoxNTUzNDg1MjQ3LCJleHAiOjE1NTM1NzE2NDd9.TBO2RbLIESO5h3n8Cop4DVYJNhI46nfaAIuzUuTJ73v5j0myplcj3amNyW_PPRxSauMhG5gwhkSrYHgnO-f423a7YnGW1SmfqmpEFd8s5j1yGRIytJsuaVD0B5nfrjSkS4Bu5lV8J2pYmnanZkr_Mo6oj2_IhITk0lVBTgri-PTUfGKNCFfCI3bpFH2UwbvNzJD6wniW5C9rOG7oBMSbDTOK2HJK_3mf1DifzoH0iQY2r5fyJzomtYDd2Z4BGtPnWpU6wAF3rcfOYqYDW1KA74PsPZm2kaqC7Icq1PvqFglX3QwpmvQqpEvzWSNS3nNFui5yjupkHSlXfU24CEn3EA";
        constexpr auto jwt3 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1cmwiOiJodHRwczovL2FhLnZpcnRydS5jb20vYXR0ci9zdXBlci1hZG1pbi92YWx1ZS90cnVlIiwibmFtZSI6dHJ1ZSwiaWF0IjoxNTUzNDg1MjQ3LCJleHAiOjE1NTM1NzE2NDd9.pkvAvRxU3pcqTCvUCuJtCwEg8UnXkLGKUgdH7aBnHWqCix_CXt_OqJ5T-b58xlszelyvcdmvTQxyg1_aHXOKg5wDQQaA6Ur3NsbYr3oskrPI8dE8gIK326NPpqrjrpBGGXkPoJHkXwGO5GfqtoNpuFWd8Y5UDLmH1QKegsBJQAVoV6JpWGvPyP_apAL8cNPNiTHuAL2RyE17ArhziHu6Ujaq_faJaC8sghSejGjW6SpdWiSF9Kw0rV4dZWjRsRu9qbWf3grMIMqEoP-3mSlpxhpDPWTS0hRaCnSvpneQynFvhbKMA2XA0z29Z9i6JueQisrjKVJ1PiaYvZIWNzz3OA";

        auto entityObject = EntityObject::createEntityObjectFromJson(entityObjectJsonStr);

        BOOST_TEST(entityObject.getUserId() == userId);
        BOOST_TEST(entityObject.getPublicKey() == publicKey);
        BOOST_TEST(entityObject.getCert() == cert);

        auto aliases = entityObject.getAliases();
        BOOST_CHECK(aliases.size() == 2);

        auto attributes = entityObject.getAttributesAsJWT();
        BOOST_TEST(attributes.at(0) == jwt1);
        BOOST_TEST(attributes.at(1) == jwt2);
        BOOST_TEST(attributes.at(2) == jwt3);
        BOOST_CHECK(attributes.size() == 3);


        auto entityObject1 = EntityObject{};
        auto entityObjectJsonStr1 = entityObject1.setUserId(userId)
                                                 .setAliases(alias1)
                                                 .setAliases(alias2)
                                                 .setAttributeAsJwt(jwt1)
                                                 .setAttributeAsJwt(jwt2)
                                                 .setAttributeAsJwt(jwt3)
                                                 .setPublicKey(publicKey)
                                                 .setCert(cert)
                                                 .toJsonString(true);
        std::cerr << "Entity object as json str =" << entityObjectJsonStr1 << std::endl;

        BOOST_TEST(entityObject1.getUserId() == userId);
        BOOST_TEST(entityObject1.getPublicKey() == publicKey);
        BOOST_TEST(entityObject1.getCert() == cert);

        aliases = entityObject1.getAliases();
        BOOST_CHECK(aliases.size() == 2);

        attributes = entityObject1.getAttributesAsJWT();
        BOOST_TEST(attributes.at(0) == jwt1);
        BOOST_TEST(attributes.at(1) == jwt2);
        BOOST_TEST(attributes.at(2) == jwt3);
        BOOST_CHECK(attributes.size() == 3);
    }
BOOST_AUTO_TEST_SUITE_END()