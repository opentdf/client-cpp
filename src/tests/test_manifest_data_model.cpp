//
//  TDF SDK
//
//  Created by Sujan Reddy on 2023/03/28
//  Copyright 2023 Virtru Corporation
//

#define BOOST_TEST_MODULE test_jwt_suite

#include <jwt-cpp/jwt.h>
#include <chrono>
#include "manifest_data_model.h"
#include "sdk_constants.h"

#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(test_manifest_data_model_suite)

    using namespace std::string_literals;
    using namespace virtru;

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

    BOOST_AUTO_TEST_CASE(test_manifest_data_model_json) {
        auto dataModel = ManifestDataModel::CreateModelFromJson(manifestInJson);

        BOOST_TEST(dataModel.payload.type == kPayloadReference);
        BOOST_TEST(dataModel.payload.url == kTDFPayloadFileName);
        BOOST_TEST(dataModel.payload.protocol == kPayloadZipProtcol);
        BOOST_TEST(dataModel.payload.isEncrypted == true);

        BOOST_TEST(dataModel.encryptionInformation.keyAccessType == kSplitKeyType);

        auto firstKeyAccessObject = dataModel.encryptionInformation.keyAccessObjects.front();
        BOOST_TEST(firstKeyAccessObject.keyType == kKeyAccessWrapped);
        BOOST_TEST(firstKeyAccessObject.url == "http://kas.example.com:4000");
        BOOST_TEST(firstKeyAccessObject.protocol == kKasProtocol);
        BOOST_TEST(firstKeyAccessObject.wrappedKey == "Y4wTa8tdKqSS3DUNMKTIUQq8Ti/WFrq26DRemybBgBcL/CyUZ98hFjDQgy4csBusEqwQ5zG+UAoRgkLkHiAw7hNAayAUCVRw6aUYRF4LWfcs2BM9k6d3bHqun0v5w==");
        BOOST_TEST(firstKeyAccessObject.policyBinding == "ZGMwNGExZjg0ODFjNDEzZTk5NjdkZmI5MWFjN2Y1MzI0MTliNjM5MmRlMTlhYWM0NjNjN2VjYTVkOTJlODcwNA==");
        BOOST_TEST(firstKeyAccessObject.encryptedMetadata == "OEOqJCS6mZsmLWJ38lh6EN2lDUA8OagL/OxQRQ==");


        BOOST_TEST(dataModel.encryptionInformation.method.algorithm == kCipherAlgorithmGCM);
        BOOST_TEST(dataModel.encryptionInformation.method.isStreamable == true);
        BOOST_TEST(dataModel.encryptionInformation.method.iv == "OEOqJCS6mZsmLWJ3");

        auto integrityInformation = dataModel.encryptionInformation.integrityInformation;
        BOOST_TEST(integrityInformation.rootSignature.algorithm == "HS256");
        BOOST_TEST(integrityInformation.rootSignature.signature == "YjliMzAyNjg4NzA0NzUyYmUwNzY1YWE4MWNhNDRmMDZjZDU3OWMyYTMzNjNlNDYyNTM4MDA4YjQxYTdmZmFmOA==");

        BOOST_TEST(integrityInformation.segmentSizeDefault == 1000000);
        BOOST_TEST(integrityInformation.segmentHashAlg == "GMAC");
        BOOST_TEST(integrityInformation.encryptedSegmentSizeDefault == 1000028);

        auto firstSegment = integrityInformation.segments.front();
        BOOST_TEST(firstSegment.hash == "ZmQyYjY2ZDgxY2IzNGNmZTI3ODFhYTk2ZjJhNWNjODA=");
        BOOST_TEST(firstSegment.segmentSize == 14056);
        BOOST_TEST(firstSegment.encryptedSegmentSize == 14084);

        BOOST_TEST_MESSAGE(dataModel.toJson());
    }

BOOST_AUTO_TEST_SUITE_END()
