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

    static const std::string manifest = R"({"name":"John", "age":30, "car":null})";
    static const std::string payload = R"(abcdefghijklmnopqrstuvwxyz)";
    static const std::string tdfXML = R"(<?xml version="1.0" encoding="UTF-8"?>
<TrustedDataObject><EncryptionInformation>eyJuYW1lIjoiSm9obiIsICJhZ2UiOjMwLCAiY2FyIjpudWxsfQ==</EncryptionInformation><Base64BinaryPayload mediaType="text/plain" filename="0.payload" isEncrypted="true">YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=</Base64BinaryPayload></TrustedDataObject>
)";

    BOOST_AUTO_TEST_CASE(test_tdf_xml_writer) {

        // Create output provider
        std::ostringstream oStringStream;
        StreamOutputProvider outputProvider{oStringStream};

        TDFXMLWriter tdfxmlWriter{outputProvider, kTDFManifestFileName, kTDFPayloadFileName};
        std::string localCopy(manifest);
        tdfxmlWriter.setPayloadSize(payload.size());
        tdfxmlWriter.appendManifest(std::move(localCopy));
        tdfxmlWriter.appendPayload(toBytes(payload));
        tdfxmlWriter.finish();
        BOOST_TEST(oStringStream.str() == tdfXML);
    }

    BOOST_AUTO_TEST_CASE(test_tdf_xml_reader) {

        std::string actualPayload;

        std::istringstream inputStream(tdfXML);
        StreamInputProvider inputProvider{inputStream};
        TDFXMLReader tdfxmlReader{inputProvider};

        BOOST_TEST(tdfxmlReader.getManifest() == manifest);
        BOOST_TEST(tdfxmlReader.getPayloadSize() == (std::uint64_t)26);

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
