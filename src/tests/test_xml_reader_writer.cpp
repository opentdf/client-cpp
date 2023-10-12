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
#include "tdf_xml_validator.h"
#include "stream_io_provider.h"
#include "file_io_provider.h"
#include "support/test_utils.h"
#include "tdf_client.h"

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
		"keyAccess": [{
			"type": "wrapped",
			"url": "http://kas.example.com:4000",
			"protocol": "kas",
			"wrappedKey": "Y4wTa8tdKqSS3DUNMKTIUQq8Ti/WFrq26DRemybBgBcL/CyUZ98hFjDQgy4csBusEqwQ5zG+UAoRgkLkHiAw7hNAayAUCVRw6aUYRF4LWfcs2BM9k6d3bHqun0v5w==",
			"policyBinding": "ZGMwNGExZjg0ODFjNDEzZTk5NjdkZmI5MWFjN2Y1MzI0MTliNjM5MmRlMTlhYWM0NjNjN2VjYTVkOTJlODcwNA==",
			"encryptedMetadata": "OEOqJCS6mZsmLWJ38lh6EN2lDUA8OagL/OxQRQ=="
		}],
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
			"segments": [{
				"hash": "ZmQyYjY2ZDgxY2IzNGNmZTI3ODFhYTk2ZjJhNWNjODA=",
				"segmentSize": 14056,
				"encryptedSegmentSize": 14084
			}],
			"encryptedSegmentSizeDefault": 1000028
		},
		"policy": "eyJ1dWlkIjoiNjEzMzM0NjYtNGYwYS00YTEyLTk1ZmItYjZkOGJkMGI4YjI2IiwiYm9keSI6eyJhdHRyaWJ1dGVzIjpbXSwiZGlzc2VtIjpbInVzZXJAdmlydHJ1LmNvbSJdfX0="
	},
	"assertions": [{
			"EncryptionInformation": {},
			"id": "assertion1",
			"scope": "TDO",
			"statement": {
				"isEncrypted": false,
				"type": "StringStatement",
				"value": "This is the first\n            assertion"
			},
			"statementMetadata": [],
			"type": "Base"
		},
		{
			"EncryptionInformation": {},
			"id": "assertion2",
			"scope": "TDO",
			"statement": {
				"isEncrypted": false,
				"type": "Base64BinaryStatement",
				"value": "VGhpcyBpcyBhIGJpbmFyeSBzdGF0ZW1lbnQ="
			},
			"statementMetadata": [],
			"type": "Base"
		},
		{
			"EncryptionInformation": {},
			"id": "myID3",
			"scope": "TDO",
			"statement": {
				"isEncrypted": true,
				"mediaType": "application/xml",
				"type": "ReferenceStatement",
				"uri": "https://someurl.com/somereferencestatement.xml"
			},
			"statementMetadata": [],
			"type": "Base"
		},
		{
			"EncryptionInformation": {},
			"id": "myID4",
			"scope": "PAYL",
			"statement": {
				"isEncrypted": false,
				"type": "StructuredStatement",
				"value": "somexml"
			},
			"statementMetadata": [],
			"type": "Base"
		},
		{
			"EncryptionInformation": {},
			"appliesToState": "unencrypted",
			"scope": "TDO",
			"type": "Handling",
			"statement": {
				"type": "HandlingStatement",
				"value": "PGVkaDpFZGggeG1sbnM6ZWRoPSJ1cm46dXM6Z292OmljOmVkaCIgeG1sbnM6dXNhZ2VuY3k9InVybjp1czpnb3Y6aWM6dXNhZ2VuY3kiIHhtbG5zOmljaWQ9InVybjp1czpnb3Y6aWM6aWQiIHhtbG5zOmFyaD0idXJuOnVzOmdvdjppYzphcmgiIHhtbG5zOmlzbT0idXJuOnVzOmdvdjppYzppc20iIHhtbG5zOm50az0idXJuOnVzOmdvdjppYzpudGsiIHVzYWdlbmN5OkNFU1ZlcnNpb249IjIwMTYwOSIgaWNpZDpERVNWZXJzaW9uPSIxIiBlZGg6REVTVmVyc2lvbj0iMjAxNjA5IiBhcmg6REVTVmVyc2lvbj0iMyIgaXNtOkRFU1ZlcnNpb249IjIwMTYwOS4yMDE3MDciIGlzbTpJU01DQVRDRVNWZXJzaW9uPSIyMDE3MDkiIG50azpERVNWZXJzaW9uPSIyMDE1MDgiPgogICAgICAgICAgICAgICAgPGljaWQ6SWRlbnRpZmllcj5ndWlkZTovLzk5OTk5MC9zb21ldGhpbmc8L2ljaWQ6SWRlbnRpZmllcj4KICAgICAgICAgICAgICAgIDxlZGg6RGF0YUl0ZW1DcmVhdGVEYXRlVGltZT4yMDEyLTA1LTI4VDE1OjA2OjAwWjwvZWRoOkRhdGFJdGVtQ3JlYXRlRGF0ZVRpbWU+CiAgICAgICAgICAgICAgICA8ZWRoOlJlc3BvbnNpYmxlRW50aXR5IGVkaDpyb2xlPSJDdXN0b2RpYW4iPgogICAgICAgICAgICAgICAgICAgIDxlZGg6Q291bnRyeT5VU0E8L2VkaDpDb3VudHJ5PgogICAgICAgICAgICAgICAgICAgIDxlZGg6T3JnYW5pemF0aW9uPkROSTwvZWRoOk9yZ2FuaXphdGlvbj4KICAgICAgICAgICAgICAgIDwvZWRoOlJlc3BvbnNpYmxlRW50aXR5PgogICAgICAgICAgICAgICAgPGFyaDpTZWN1cml0eSBpc206Y29tcGxpZXNXaXRoPSJVU0dvdiBVU0lDIiBpc206cmVzb3VyY2VFbGVtZW50PSJ0cnVlIiBpc206Y3JlYXRlRGF0ZT0iMjAxMi0wNS0yOCIgaXNtOmNsYXNzaWZpY2F0aW9uPSJVIiBpc206b3duZXJQcm9kdWNlcj0iVVNBIi8+CiAgICAgICAgICAgIDwvZWRoOkVkaD4="
			}
		},
		{
			"EncryptionInformation": {},
			"appliesToState": "unencrypted",
			"scope": "PAYL",
			"type": "Handling",
			"statement": {
				"type": "HandlingStatement",
				"value": "PGVkaDpFZGggeG1sbnM6ZWRoPSJ1cm46dXM6Z292OmljOmVkaCIgeG1sbnM6dXNhZ2VuY3k9InVybjp1czpnb3Y6aWM6dXNhZ2VuY3kiIHhtbG5zOmljaWQ9InVybjp1czpnb3Y6aWM6aWQiIHhtbG5zOmFyaD0idXJuOnVzOmdvdjppYzphcmgiIHhtbG5zOmlzbT0idXJuOnVzOmdvdjppYzppc20iIHhtbG5zOm50az0idXJuOnVzOmdvdjppYzpudGsiIHVzYWdlbmN5OkNFU1ZlcnNpb249IjIwMTYwOSIgaWNpZDpERVNWZXJzaW9uPSIxIiBlZGg6REVTVmVyc2lvbj0iMjAxNjA5IiBhcmg6REVTVmVyc2lvbj0iMyIgaXNtOkRFU1ZlcnNpb249IjIwMTYwOS4yMDE3MDciIGlzbTpJU01DQVRDRVNWZXJzaW9uPSIyMDE3MDkiIG50azpERVNWZXJzaW9uPSIyMDE1MDgiPgogICAgICAgICAgICAgICAgPGljaWQ6SWRlbnRpZmllcj5ndWlkZTovLzk5OTk5MC9zb21ldGhpbmc8L2ljaWQ6SWRlbnRpZmllcj4KICAgICAgICAgICAgICAgIDxlZGg6RGF0YUl0ZW1DcmVhdGVEYXRlVGltZT4yMDEyLTA1LTI4VDE1OjA2OjAwWjwvZWRoOkRhdGFJdGVtQ3JlYXRlRGF0ZVRpbWU+CiAgICAgICAgICAgICAgICA8ZWRoOlJlc3BvbnNpYmxlRW50aXR5IGVkaDpyb2xlPSJDdXN0b2RpYW4iPgogICAgICAgICAgICAgICAgICAgIDxlZGg6Q291bnRyeT5VU0E8L2VkaDpDb3VudHJ5PgogICAgICAgICAgICAgICAgICAgIDxlZGg6T3JnYW5pemF0aW9uPkROSTwvZWRoOk9yZ2FuaXphdGlvbj4KICAgICAgICAgICAgICAgIDwvZWRoOlJlc3BvbnNpYmxlRW50aXR5PgogICAgICAgICAgICAgICAgPGFyaDpTZWN1cml0eSBpc206Y29tcGxpZXNXaXRoPSJVU0dvdiBVU0lDIiBpc206cmVzb3VyY2VFbGVtZW50PSJ0cnVlIiBpc206Y3JlYXRlRGF0ZT0iMjAxMi0wNS0yOCIgaXNtOmNsYXNzaWZpY2F0aW9uPSJVIiBpc206b3duZXJQcm9kdWNlcj0iVVNBIi8+CiAgICAgICAgICAgIDwvZWRoOkVkaD4="
			}
		},
		{
			"EncryptionInformation": {},
			"appliesToState": "encrypted",
			"scope": "PAYL",
			"type": "Handling",
			"statement": {
				"type": "HandlingStatement",
				"value": "PGVkaDpFZGggeG1sbnM6ZWRoPSJ1cm46dXM6Z292OmljOmVkaCIgeG1sbnM6dXNhZ2VuY3k9InVybjp1czpnb3Y6aWM6dXNhZ2VuY3kiIHhtbG5zOmljaWQ9InVybjp1czpnb3Y6aWM6aWQiIHhtbG5zOmFyaD0idXJuOnVzOmdvdjppYzphcmgiIHhtbG5zOmlzbT0idXJuOnVzOmdvdjppYzppc20iIHhtbG5zOm50az0idXJuOnVzOmdvdjppYzpudGsiIHVzYWdlbmN5OkNFU1ZlcnNpb249IjIwMTYwOSIgaWNpZDpERVNWZXJzaW9uPSIxIiBlZGg6REVTVmVyc2lvbj0iMjAxNjA5IiBhcmg6REVTVmVyc2lvbj0iMyIgaXNtOkRFU1ZlcnNpb249IjIwMTYwOS4yMDE3MDciIGlzbTpJU01DQVRDRVNWZXJzaW9uPSIyMDE3MDkiIG50azpERVNWZXJzaW9uPSIyMDE1MDgiPgogICAgICAgICAgICAgICAgPGljaWQ6SWRlbnRpZmllcj5ndWlkZTovLzk5OTk5MC9zb21ldGhpbmc8L2ljaWQ6SWRlbnRpZmllcj4KICAgICAgICAgICAgICAgIDxlZGg6RGF0YUl0ZW1DcmVhdGVEYXRlVGltZT4yMDEyLTA1LTI4VDE1OjA2OjAwWjwvZWRoOkRhdGFJdGVtQ3JlYXRlRGF0ZVRpbWU+CiAgICAgICAgICAgICAgICA8ZWRoOlJlc3BvbnNpYmxlRW50aXR5IGVkaDpyb2xlPSJDdXN0b2RpYW4iPgogICAgICAgICAgICAgICAgICAgIDxlZGg6Q291bnRyeT5VU0E8L2VkaDpDb3VudHJ5PgogICAgICAgICAgICAgICAgICAgIDxlZGg6T3JnYW5pemF0aW9uPkROSTwvZWRoOk9yZ2FuaXphdGlvbj4KICAgICAgICAgICAgICAgIDwvZWRoOlJlc3BvbnNpYmxlRW50aXR5PgogICAgICAgICAgICAgICAgPGFyaDpTZWN1cml0eSBpc206Y29tcGxpZXNXaXRoPSJVU0dvdiBVU0lDIiBpc206cmVzb3VyY2VFbGVtZW50PSJ0cnVlIiBpc206Y3JlYXRlRGF0ZT0iMjAxMi0wNS0yOCIgaXNtOmNsYXNzaWZpY2F0aW9uPSJVIiBpc206b3duZXJQcm9kdWNlcj0iVVNBIi8+CiAgICAgICAgICAgIDwvZWRoOkVkaD4="
			}
		}
	]
})";

    static const std::string payload = R"(abcdefghijklmnopqrstuvwxyz)";
    static const std::string tdfXML = R"(<?xml version="1.0" encoding="UTF-8"?>
<tdf:TrustedDataObject xmlns="urn:us:gov:ic:tdf" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:tdf="urn:us:gov:ic:tdf"><tdf:HandlingAssertion tdf:scope="TDO" tdf:appliesToState="unencrypted"><tdf:HandlingStatement><edh:Edh xmlns:edh="urn:us:gov:ic:edh" xmlns:usagency="urn:us:gov:ic:usagency" xmlns:icid="urn:us:gov:ic:id" xmlns:arh="urn:us:gov:ic:arh" xmlns:ism="urn:us:gov:ic:ism" xmlns:ntk="urn:us:gov:ic:ntk" usagency:CESVersion="201609" icid:DESVersion="1" edh:DESVersion="201609" arh:DESVersion="3" ism:DESVersion="201609.201707" ism:ISMCATCESVersion="201709" ntk:DESVersion="201508">
                <icid:Identifier>guide://999990/something</icid:Identifier>
                <edh:DataItemCreateDateTime>2012-05-28T15:06:00Z</edh:DataItemCreateDateTime>
                <edh:ResponsibleEntity edh:role="Custodian">
                    <edh:Country>USA</edh:Country>
                    <edh:Organization>DNI</edh:Organization>
                </edh:ResponsibleEntity>
                <arh:Security ism:compliesWith="USGov USIC" ism:resourceElement="true" ism:createDate="2012-05-28" ism:classification="U" ism:ownerProducer="USA"/>
            </edh:Edh></tdf:HandlingStatement></tdf:HandlingAssertion><tdf:HandlingAssertion tdf:scope="PAYL" tdf:appliesToState="unencrypted"><tdf:HandlingStatement><edh:Edh xmlns:edh="urn:us:gov:ic:edh" xmlns:usagency="urn:us:gov:ic:usagency" xmlns:icid="urn:us:gov:ic:id" xmlns:arh="urn:us:gov:ic:arh" xmlns:ism="urn:us:gov:ic:ism" xmlns:ntk="urn:us:gov:ic:ntk" usagency:CESVersion="201609" icid:DESVersion="1" edh:DESVersion="201609" arh:DESVersion="3" ism:DESVersion="201609.201707" ism:ISMCATCESVersion="201709" ntk:DESVersion="201508">
                <icid:Identifier>guide://999990/something</icid:Identifier>
                <edh:DataItemCreateDateTime>2012-05-28T15:06:00Z</edh:DataItemCreateDateTime>
                <edh:ResponsibleEntity edh:role="Custodian">
                    <edh:Country>USA</edh:Country>
                    <edh:Organization>DNI</edh:Organization>
                </edh:ResponsibleEntity>
                <arh:Security ism:compliesWith="USGov USIC" ism:resourceElement="true" ism:createDate="2012-05-28" ism:classification="U" ism:ownerProducer="USA"/>
            </edh:Edh></tdf:HandlingStatement></tdf:HandlingAssertion><tdf:HandlingAssertion tdf:scope="PAYL" tdf:appliesToState="encrypted"><tdf:HandlingStatement><edh:Edh xmlns:edh="urn:us:gov:ic:edh" xmlns:usagency="urn:us:gov:ic:usagency" xmlns:icid="urn:us:gov:ic:id" xmlns:arh="urn:us:gov:ic:arh" xmlns:ism="urn:us:gov:ic:ism" xmlns:ntk="urn:us:gov:ic:ntk" usagency:CESVersion="201609" icid:DESVersion="1" edh:DESVersion="201609" arh:DESVersion="3" ism:DESVersion="201609.201707" ism:ISMCATCESVersion="201709" ntk:DESVersion="201508">
                <icid:Identifier>guide://999990/something</icid:Identifier>
                <edh:DataItemCreateDateTime>2012-05-28T15:06:00Z</edh:DataItemCreateDateTime>
                <edh:ResponsibleEntity edh:role="Custodian">
                    <edh:Country>USA</edh:Country>
                    <edh:Organization>DNI</edh:Organization>
                </edh:ResponsibleEntity>
                <arh:Security ism:compliesWith="USGov USIC" ism:resourceElement="true" ism:createDate="2012-05-28" ism:classification="U" ism:ownerProducer="USA"/>
            </edh:Edh></tdf:HandlingStatement></tdf:HandlingAssertion><tdf:Assertion tdf:scope="TDO"><tdf:StringStatement tdf:isEncrypted="false">This is the first
            assertion</tdf:StringStatement></tdf:Assertion><tdf:Assertion tdf:scope="TDO"><tdf:Base64BinaryStatement tdf:isEncrypted="false">VGhpcyBpcyBhIGJpbmFyeSBzdGF0ZW1lbnQ=</tdf:Base64BinaryStatement></tdf:Assertion><tdf:Assertion tdf:scope="TDO"><tdf:ReferenceStatement tdf:isEncrypted="true" tdf:mediaType="application/xml" tdf:uri="https://someurl.com/somereferencestatement.xml"/></tdf:Assertion><tdf:Assertion tdf:scope="PAYL"><tdf:StructuredStatement tdf:isEncrypted="false">somexml</tdf:StructuredStatement></tdf:Assertion><tdf:EncryptionInformation><tdf:KeyAccess><tdf:WrappedPDPKey><tdf:EncryptedPolicyObject>eyJpbnRlZ3JpdHlJbmZvcm1hdGlvbiI6eyJlbmNyeXB0ZWRTZWdtZW50U2l6ZURlZmF1bHQiOjEwMDAwMjgsInJvb3RTaWduYXR1cmUiOnsiYWxnIjoiSFMyNTYiLCJzaWciOiJZamxpTXpBeU5qZzROekEwTnpVeVltVXdOelkxWVdFNE1XTmhORFJtTURaalpEVTNPV015WVRNek5qTmxORFl5TlRNNE1EQTRZalF4WVRkbVptRm1PQT09In0sInNlZ21lbnRIYXNoQWxnIjoiR01BQyIsInNlZ21lbnRTaXplRGVmYXVsdCI6MTAwMDAwMCwic2VnbWVudHMiOlt7ImVuY3J5cHRlZFNlZ21lbnRTaXplIjoxNDA4NCwiaGFzaCI6IlptUXlZalkyWkRneFkySXpOR05tWlRJM09ERmhZVGsyWmpKaE5XTmpPREE9Iiwic2VnbWVudFNpemUiOjE0MDU2fV19LCJrZXlBY2Nlc3MiOlt7ImVuY3J5cHRlZE1ldGFkYXRhIjoiT0VPcUpDUzZtWnNtTFdKMzhsaDZFTjJsRFVBOE9hZ0wvT3hRUlE9PSIsInBvbGljeUJpbmRpbmciOiJaR013TkdFeFpqZzBPREZqTkRFelpUazVOamRrWm1JNU1XRmpOMlkxTXpJME1UbGlOak01TW1SbE1UbGhZV00wTmpOak4yVmpZVFZrT1RKbE9EY3dOQT09IiwicHJvdG9jb2wiOiJrYXMiLCJ0eXBlIjoid3JhcHBlZCIsInVybCI6Imh0dHA6Ly9rYXMuZXhhbXBsZS5jb206NDAwMCIsIndyYXBwZWRLZXkiOiJZNHdUYTh0ZEtxU1MzRFVOTUtUSVVRcThUaS9XRnJxMjZEUmVteWJCZ0JjTC9DeVVaOThoRmpEUWd5NGNzQnVzRXF3UTV6RytVQW9SZ2tMa0hpQXc3aE5BYXlBVUNWUnc2YVVZUkY0TFdmY3MyQk05azZkM2JIcXVuMHY1dz09In1dLCJwb2xpY3kiOiJleUoxZFdsa0lqb2lOakV6TXpNME5qWXROR1l3WVMwMFlURXlMVGsxWm1JdFlqWmtPR0prTUdJNFlqSTJJaXdpWW05a2VTSTZleUpoZEhSeWFXSjFkR1Z6SWpwYlhTd2laR2x6YzJWdElqcGJJblZ6WlhKQWRtbHlkSEoxTG1OdmJTSmRmWDA9In0=</tdf:EncryptedPolicyObject></tdf:WrappedPDPKey></tdf:KeyAccess><tdf:EncryptionMethod tdf:algorithm="AES-256-GCM"><tdf:KeySize>32</tdf:KeySize><tdf:IVParams>OEOqJCS6mZsmLWJ3</tdf:IVParams></tdf:EncryptionMethod></tdf:EncryptionInformation><tdf:Base64BinaryPayload tdf:isEncrypted="true" tdf:mediaType="application/octet-stream">YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=</tdf:Base64BinaryPayload></tdf:TrustedDataObject>
)";
    BOOST_AUTO_TEST_CASE(test_tdf_xml_writer) {

        // Create output provider
        std::ostringstream oStringStream;
        StreamOutputProvider outputProvider{oStringStream};

        TDFXMLWriter tdfxmlWriter{outputProvider};
        auto dataModel = ManifestDataModel::CreateModelFromJson(manifestInJson);
        tdfxmlWriter.setPayloadSize(payload.size());
        tdfxmlWriter.appendManifest(dataModel);
        tdfxmlWriter.appendPayload(toBytes(payload));
        tdfxmlWriter.finish();

        std::cout << "ICTDF XML:\n" << oStringStream.str() << std::endl;

        BOOST_TEST(oStringStream.str() == tdfXML);
    }

    BOOST_AUTO_TEST_CASE(test_tdf_advaced_xml_writer) {

        std::string currentDir = TestUtils::getCurrentWorkingDir();

        // TODO: BUGBUG: We should use std::filesystem once all the compilers catch up.
#ifdef _WINDOWS
        std::string inPathXML {currentDir };
        inPathXML.append("\\data\\tdf.ictdf");
#else
        std::string inPathXML{currentDir};
        inPathXML.append("/data/tdf.ictdf");
#endif

        TDFClient::convertXmlToJson(inPathXML, "converted_tdf.tdf");

        FileInputProvider fileInputProvider{inPathXML};
        TDFXMLReader tdfXMLReader{fileInputProvider};



        auto dataModel = tdfXMLReader.getManifest();

        // XML
        {
            std::ostringstream oStringStream;
            StreamOutputProvider outputProvider{oStringStream};
            TDFXMLWriter tdfxmlWriter{outputProvider};
            tdfxmlWriter.setPayloadSize(payload.size());
            tdfxmlWriter.appendManifest(dataModel);
            tdfxmlWriter.appendPayload(toBytes(payload));
            tdfxmlWriter.finish();

            std::cout << "ICTDF XML:\n" << oStringStream.str() << std::endl;


            {
                std::istringstream inputStream(oStringStream.str());
                StreamInputProvider inputProvider{inputStream};
                TDFXMLReader archiveReader{inputProvider};
                auto model = archiveReader.getManifest();
            }
        }

        // Json
        {
            std::ostringstream oStringStream;
            StreamOutputProvider outputProvider{oStringStream};
            TDFArchiveWriter tdfArchiveWriter{&outputProvider,
                                              kTDFManifestFileName,
                                              kTDFPayloadFileName};
            tdfArchiveWriter.setPayloadSize(payload.size());
            tdfArchiveWriter.appendManifest(dataModel);
            tdfArchiveWriter.appendPayload(toBytes(payload));
            tdfArchiveWriter.finish();

            std::cout << "TDF:\n" << oStringStream.str() << std::endl;
        }

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


    BOOST_AUTO_TEST_CASE(test_tdf_xml_validation) {

        const char *xmlfilegood = "data/good.tdf.ictdf";
        const char *xmlfilebad = "data/invalid_xml_tdf.tdf";

        const char *schemafile = "data/IC-TDF/Schema/IC-TDF/IC-TDF.xsd";

        bool result;

        BOOST_TEST_MESSAGE("Beginning test of valid XML input");
        std::cout << "Beginning test of valid XML input" << std::endl;
        try {
            std::istringstream inputStream(tdfXML);
            StreamInputProvider inputProvider{inputStream};
            TDFXMLReader tdfxmlReader{inputProvider};

            TDFXMLValidator validator;
            validator.setSchema(schemafile);

            result = validator.validate(xmlfilegood);
            BOOST_TEST(result == true);
        } catch (std::exception e) {
            LogDebug(e.what());
            std::ostringstream oss;
            oss << e.what();
            BOOST_FAIL("Caught exception: " + oss.str());
        }
        BOOST_TEST_MESSAGE("End of test of valid XML input");
        std::cout << "End of test of valid XML input" << std::endl;

        BOOST_TEST_MESSAGE("Beginning test of INvalid XML input");
        std::cout << "Beginning test of INvalid XML input" << std::endl;
        try {
            std::istringstream inputStream(tdfXML);
            StreamInputProvider inputProvider{inputStream};
            TDFXMLReader tdfxmlReader{inputProvider};

            TDFXMLValidator validator;
            validator.setSchema(schemafile);

            result = validator.validate(xmlfilebad);
            BOOST_TEST(result == false);
            BOOST_FAIL("Should throw exception on bad input");
        } catch (std::exception e) {
            // Correct response is to throw an exception on bad input
            LogDebug(e.what());
            std::ostringstream oss;
            oss << e.what();
            std::cout << "Caught exception: " << oss.str() << std::endl;
        }
        BOOST_TEST_MESSAGE("End of test of INvalid XML input");
        std::cout << "End of test of INvalid XML input" << std::endl;
    }

BOOST_AUTO_TEST_SUITE_END()
