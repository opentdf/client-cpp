//
//  TDF SDK
//
//  Created by Sujan Reddy on 2021/12/14
//  Copyright 2021 Virtru Corporation
//

#define BOOST_TEST_MODULE test_xml_reader_writer

#include "sdk_constants.h"
#include "tdf_xml_reader.h"
#include "tdf_xml_writer.h"
#include "stream_io_provider.h"

#include <ostream>
#include <boost/test/included/unit_test.hpp>

using namespace virtru;

BOOST_AUTO_TEST_SUITE(test_xml_reader_writer_suite)

    using namespace virtru;
    using namespace virtru::crypto;

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

    static const std::string payload = R"(abcdefghijklmnopqrstuvwxyz)";
    static const std::string tdfXML = R"(<?xml version="1.0" encoding="UTF-8"?>
<TrustedDataCollection xmlns:tdf="urn:us:gov:ic:tdf"><TrustedDataObject><ReferenceValuePayload isEncrypted="true" mediaType="application/octet-stream"/><EncryptionInformation><KeyAccess><WrappedPDPKey><KeyValue>Y4wTa8tdKqSS3DUNMKTIUQq8Ti/WFrq26DRemybBgBcL/CyUZ98hFjDQgy4csBusEqwQ5zG+UAoRgkLkHiAw7hNAayAUCVRw6aUYRF4LWfcs2BM9k6d3bHqun0v5w==</KeyValue><EncryptedPolicyObject>PD94bWwgdmVyc2lvbj0iMS4wIj8+CjxFbmNyeXB0ZWRQb2xpY3lPYmplY3Q+PHBvbGljeT5leUoxZFdsa0lqb2lOakV6TXpNME5qWXROR1l3WVMwMFlURXlMVGsxWm1JdFlqWmtPR0prTUdJNFlqSTJJaXdpWW05a2VTSTZleUpoZEhSeWFXSjFkR1Z6SWpwYlhTd2laR2x6YzJWdElqcGJJblZ6WlhKQWRtbHlkSEoxTG1OdmJTSmRmWDA9PC9wb2xpY3k+PHBvbGljeUJpbmRpbmc+WkdNd05HRXhaamcwT0RGak5ERXpaVGs1Tmpka1ptSTVNV0ZqTjJZMU16STBNVGxpTmpNNU1tUmxNVGxoWVdNME5qTmpOMlZqWVRWa09USmxPRGN3TkE9PTwvcG9saWN5QmluZGluZz48ZW5jcnlwdGVkTWV0YWRhdGE+T0VPcUpDUzZtWnNtTFdKMzhsaDZFTjJsRFVBOE9hZ0wvT3hRUlE9PTwvZW5jcnlwdGVkTWV0YWRhdGE+PC9FbmNyeXB0ZWRQb2xpY3lPYmplY3Q+Cg==</EncryptedPolicyObject><EncryptionInformation><KeyAccess><RemoteStoredKey protocol="kas" uri="http://kas.example.com:4000"/></KeyAccess><EncryptionMethod algorithm="AES-256-GCM"><KeySize>32</KeySize><IVParams>OEOqJCS6mZsmLWJ3</IVParams><AuthenticationTag>B20abww4lLmNOqa43sas</AuthenticationTag></EncryptionMethod></EncryptionInformation></WrappedPDPKey></KeyAccess></EncryptionInformation><Base64BinaryPayload>YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=</Base64BinaryPayload></TrustedDataObject></TrustedDataCollection>
)";
    BOOST_AUTO_TEST_CASE(test_tdf_xml_writer) {

        // Create output provider
        std::ostringstream oStringStream;
        StreamOutputProvider outputProvider{oStringStream};

        TDFXMLWriter tdfxmlWriter{outputProvider, kTDFManifestFileName, kTDFPayloadFileName};
        auto dataModel = ManifestDataModel::CreateModelFromJson(manifestInJson);
        tdfxmlWriter.setPayloadSize(payload.size());
        tdfxmlWriter.appendManifest(dataModel);
        tdfxmlWriter.appendPayload(toBytes(payload));
        tdfxmlWriter.finish();

        std::cout << "ICTDF XML:\n" << oStringStream.str() << std::endl;

        BOOST_TEST(oStringStream.str() == tdfXML);
    }

    BOOST_AUTO_TEST_CASE(test_tdf_xml_reader) {

        std::string actualPayload;

        std::istringstream inputStream(tdfXML);
        StreamInputProvider inputProvider{inputStream};
        TDFXMLReader tdfxmlReader{inputProvider};

        auto dataModel1 = tdfxmlReader.getManifest();
        auto dataModel2 = ManifestDataModel::CreateModelFromJson(manifestInJson);
        BOOST_TEST(dataModel1.encryptionInformation.policy == dataModel2.encryptionInformation.policy);
        BOOST_TEST(tdfxmlReader.getPayloadSize() == 26);

        auto index = 0;
        std::string  payloadBuffer;
        payloadBuffer.resize(10);

        auto wBytes = toWriteableBytes(payloadBuffer);
        tdfxmlReader.readPayload(index, payloadBuffer.size(), wBytes);
        index +=  payloadBuffer.size();
        BOOST_TEST(wBytes.size() == 10);
        actualPayload.append(reinterpret_cast<const char*>(wBytes.data()), wBytes.size());


        wBytes = toWriteableBytes(payloadBuffer);
        tdfxmlReader.readPayload(index, payloadBuffer.size(), wBytes);
        index +=  payloadBuffer.size();
        BOOST_TEST(wBytes.size() == 10);
        actualPayload.append(reinterpret_cast<const char*>(wBytes.data()), wBytes.size());

        payloadBuffer.resize(6);
        wBytes = toWriteableBytes(payloadBuffer);
        tdfxmlReader.readPayload(index, payloadBuffer.size(), wBytes);
        actualPayload.append(reinterpret_cast<const char*>(wBytes.data()), wBytes.size());

        BOOST_TEST(actualPayload == payload);
    }

BOOST_AUTO_TEST_SUITE_END()
