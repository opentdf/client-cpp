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
<TrustedDataObject><EncryptionInformation>eyJlbmNyeXB0aW9uSW5mb3JtYXRpb24iOnsiaW50ZWdyaXR5SW5mb3JtYXRpb24iOnsiZW5jcnlwdGVkU2VnbWVudFNpemVEZWZhdWx0IjoxMDAwMDI4LCJyb290U2lnbmF0dXJlIjp7ImFsZyI6IkhTMjU2Iiwic2lnIjoiWWpsaU16QXlOamc0TnpBME56VXlZbVV3TnpZMVlXRTRNV05oTkRSbU1EWmpaRFUzT1dNeVlUTXpOak5sTkRZeU5UTTRNREE0WWpReFlUZG1abUZtT0E9PSJ9LCJzZWdtZW50SGFzaEFsZyI6IkdNQUMiLCJzZWdtZW50U2l6ZURlZmF1bHQiOjEwMDAwMDAsInNlZ21lbnRzIjpbeyJlbmNyeXB0ZWRTZWdtZW50U2l6ZSI6MTQwODQsImhhc2giOiJabVF5WWpZMlpEZ3hZMkl6TkdObVpUSTNPREZoWVRrMlpqSmhOV05qT0RBPSIsInNlZ21lbnRTaXplIjoxNDA1Nn1dfSwia2V5QWNjZXNzIjpbeyJlbmNyeXB0ZWRNZXRhZGF0YSI6Ik9FT3FKQ1M2bVpzbUxXSjM4bGg2RU4ybERVQThPYWdML094UVJRPT0iLCJwb2xpY3lCaW5kaW5nIjoiWkdNd05HRXhaamcwT0RGak5ERXpaVGs1Tmpka1ptSTVNV0ZqTjJZMU16STBNVGxpTmpNNU1tUmxNVGxoWVdNME5qTmpOMlZqWVRWa09USmxPRGN3TkE9PSIsInByb3RvY29sIjoia2FzIiwidHlwZSI6IndyYXBwZWQiLCJ1cmwiOiJodHRwOi8va2FzLmV4YW1wbGUuY29tOjQwMDAiLCJ3cmFwcGVkS2V5IjoiWTR3VGE4dGRLcVNTM0RVTk1LVElVUXE4VGkvV0ZycTI2RFJlbXliQmdCY0wvQ3lVWjk4aEZqRFFneTRjc0J1c0Vxd1E1ekcrVUFvUmdrTGtIaUF3N2hOQWF5QVVDVlJ3NmFVWVJGNExXZmNzMkJNOWs2ZDNiSHF1bjB2NXc9PSJ9XSwibWV0aG9kIjp7ImFsZ29yaXRobSI6IkFFUy0yNTYtR0NNIiwiaXNTdHJlYW1hYmxlIjp0cnVlLCJpdiI6Ik9FT3FKQ1M2bVpzbUxXSjMifSwicG9saWN5IjoiZXlKMWRXbGtJam9pTmpFek16TTBOall0TkdZd1lTMDBZVEV5TFRrMVptSXRZalprT0dKa01HSTRZakkySWl3aVltOWtlU0k2ZXlKaGRIUnlhV0oxZEdWeklqcGJYU3dpWkdsemMyVnRJanBiSW5WelpYSkFkbWx5ZEhKMUxtTnZiU0pkZlgwPSIsInR5cGUiOiJzcGxpdCJ9LCJwYXlsb2FkIjp7ImlzRW5jcnlwdGVkIjp0cnVlLCJtaW1lVHlwZSI6ImFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbSIsInByb3RvY29sIjoiemlwIiwidHlwZSI6InJlZmVyZW5jZSIsInVybCI6IjAucGF5bG9hZCJ9fQ==</EncryptionInformation><Base64BinaryPayload mediaType="text/plain" filename="0.payload" isEncrypted="true">YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=</Base64BinaryPayload></TrustedDataObject>
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
        BOOST_TEST(oStringStream.str() == tdfXML);
    }

    BOOST_AUTO_TEST_CASE(test_tdf_xml_reader) {

        std::string actualPayload;

        std::istringstream inputStream(tdfXML);
        StreamInputProvider inputProvider{inputStream};
        TDFXMLReader tdfxmlReader{inputProvider};

        auto dataModel1 = ManifestDataModel::CreateModelFromJson(tdfxmlReader.getManifest());
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
