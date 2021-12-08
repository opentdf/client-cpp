//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/05/28
//  Copyright 2019 Virtru Corporation
//

#define NOMINMAX
#define BOOST_TEST_MODULE test_html_template_suite

#include "crypto_utils.h"
#include "bytes.h"
#include "tdf_exception.h"
#include "libxml2_deleters.h"
#include "sdk_constants.h"

#include <stdio.h>
#include <stdlib.h>
#include <libxml/xmlmemory.h>
#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>
#include <libxml/xpath.h>
#include <libxml/xmlsave.h>
#include <libxml/parser.h>

#include <boost/algorithm/string.hpp>
#include <boost/test/included/unit_test.hpp>

#ifdef _WINDOWS
#include <direct.h>
#define GetCurrentDir _getcwd
#else
#include <unistd.h>
#define GetCurrentDir getcwd
#endif

std::string getCurrentWorkingDir() {
    char buff[FILENAME_MAX];
    GetCurrentDir( buff, FILENAME_MAX );
    std::string current_working_dir(buff);
    return current_working_dir;
}

BOOST_AUTO_TEST_SUITE(test_html_template_suite)

    using namespace virtru;
    using namespace virtru::crypto;

    std::string currentDir = getCurrentWorkingDir();

    BOOST_AUTO_TEST_CASE(test_html_read_template) {

        std::string sampleTemplate {currentDir };
        std::string sampleTemplateOutput {currentDir };

        // TODO: BUGBUG: We should use std::filesystem once all the compilers catch up.
#ifdef _WINDOWS
        sampleTemplate.append("\\data\\sample-template.html");
    sampleTemplateOutput.append("\\data\\sample-template-output.html");
#else
        sampleTemplate.append("/data/sample-template.html");
        sampleTemplateOutput.append("/data/sample-template-output.html");
#endif

        XMLDocFreePtr xmlDoc { htmlReadFile(sampleTemplate.data(), nullptr,
                                            HTML_PARSE_RECOVER | HTML_PARSE_NOWARNING |
                                            HTML_PARSE_NOERROR | HTML_PARSE_NODEFDTD |
                                            HTML_PARSE_NONET   | HTML_PARSE_NOIMPLIED) };

        if (!xmlDoc) {
            BOOST_FAIL(sampleTemplate + " not parsed successfully.");
        }

        // Create xpath context
        XMLXPathContextFreePtr context { xmlXPathNewContext(xmlDoc.get()) };
        if (!context) {
            BOOST_FAIL(sampleTemplate + " error in xmlXPathNewContext");
        }

        // Find the 'input' element with attribute 'id' = "data-input"
        const xmlChar *xpath = (xmlChar*) "//body/input";
        XMLXPathObjectFreePtr result { xmlXPathEvalExpression(xpath, context.get())};
        if (!result) {
            BOOST_FAIL(sampleTemplate + " error in xmlXPathEvalExpression");
        }

        if(xmlXPathNodeSetIsEmpty(result->nodesetval)) {
            BOOST_FAIL("<input> elements are missing");
        }

        xmlNodeSetPtr nodeset = result->nodesetval;
        for (int i = 0; i < nodeset->nodeNr; i++) {

            // input element.
            xmlNodePtr inputNode = nodeset->nodeTab[i];

            XMLCharFreePtr attributeValue { xmlGetProp(inputNode, reinterpret_cast<const xmlChar*>(kHTMLIdAttribute)) };


            if (attributeValue && boost::iequals(kHTMLDataInput,  (const char*)attributeValue.get())) {

                constexpr auto twoMBSize = 35 * 1024 * 1024;
                std::vector<char> twoMbBuffer(twoMBSize);
                std::fill(twoMbBuffer.begin(), twoMbBuffer.end(), 'X');

                auto encoded = base64Encode(toBytes(twoMbBuffer));

                xmlAttrPtr attribute = xmlNewProp(inputNode,
                                                  reinterpret_cast<const xmlChar*>(kHTMLValueAttribute),
                                                  reinterpret_cast<const xmlChar*>(encoded.data()));
                if (!attribute) {
                    BOOST_FAIL(" failed to add an attribute");
                }
            }
        }

        xmlOutputBufferPtr out = xmlAllocOutputBuffer(nullptr);
        if (out) {
            htmlDocContentDumpOutput(out, xmlDoc.get(), "utf8");
            const xmlChar *buffer = xmlBufferContent((xmlBuffer *) out->buffer);
            // write buffer to file

            FILE *file = fopen(sampleTemplateOutput.data(), "w");
            fputs((char *) buffer, file);
            fclose(file);

            xmlOutputBufferClose(out);
        }

    }

    BOOST_AUTO_TEST_CASE(test_tdf_html_write_and_read) {

        std::string sampleTemplate {currentDir };
        std::string sampleTemplateOutput {currentDir };

        // TODO: BUGBUG: We should use std::filesystem once all the compilers catch up.
#ifdef _WINDOWS
        sampleTemplate.append("\\data\\tdf-html-template.html");
        sampleTemplateOutput.append("\\data\\tdf-html-template-output.html");
#else
        sampleTemplate.append("/data/tdf-html-template.html");
        sampleTemplateOutput.append("/data/tdf-html-template-output.html");
#endif

        /// Read html template file.
        std::string htmlTemplateData;
        std::ifstream ifs(sampleTemplate.data(), std::ios::binary|std::ios::ate);
        if (!ifs) {
            BOOST_FAIL(sampleTemplate + " failed to open file for reading.");
        }

        std::ifstream::pos_type fileSize = ifs.tellg();
        htmlTemplateData.reserve(fileSize);
        ifs.seekg(0, std::ios::beg);
        htmlTemplateData.assign((std::istreambuf_iterator<char>(ifs)),
                         std::istreambuf_iterator<char>());

        std::vector<std::string> placeholders{ "<%= payload %>", "<%= manifest %>",
                                               "<%= transferUrl %>", "<%= transferUrl %>", "<%= transferUrl %>" };
        std::vector<std::string> htmlTemplateTokens;

        // Split the html template into tokens.
        for(auto const& placeholder: placeholders) {
            size_t placeholderPos = htmlTemplateData.find(placeholder);
            if (placeholderPos == std::string::npos) {
                BOOST_FAIL(std::to_string(placeholderPos) + " not found in the html template.");
            }

            htmlTemplateTokens.emplace_back(htmlTemplateData.substr(0, placeholderPos));
            htmlTemplateData.erase(0, placeholderPos + placeholder.length());
        }
        htmlTemplateTokens.emplace_back(htmlTemplateData);

        BOOST_CHECK(htmlTemplateTokens.size() == 6);

        ///
        /// write tdf html file.
        ///

        std::ofstream outStream { sampleTemplateOutput.data(), std::ios_base::out | std::ios_base::binary };
        if (!outStream) {
            BOOST_FAIL("Failed to open file for writing.");
        }

        auto const& token1 = htmlTemplateTokens[0];
        outStream.write(token1.data(), token1.size());

        // 1 - write base64 tdf file
        const auto input = "Hello, World!"s;
        auto encodedStr = base64Encode(toBytes(input));
        outStream.write(encodedStr.data(),encodedStr.size());

        auto const& token2 = htmlTemplateTokens[1];
        outStream.write(token2.data(), token2.size());

        // 2 - write base64 payload file.
        const auto input1 = "manifest"s;
        auto encodedStr1 = base64Encode(toBytes(input1));
        outStream.write(encodedStr1.data(),encodedStr1.size());

        auto const& token3 = htmlTemplateTokens[2];
        outStream.write(token3.data(), token3.size());

        // 3 - write the url
        const auto url = "https://local.virtru.com/secure-reader?htmlProtocol=1"s;
        outStream.write(url.data(),url.size());

        auto const& token4 = htmlTemplateTokens[3];
        outStream.write(token4.data(), token4.size());

        outStream.write(url.data(),url.size());

        auto const& token5 = htmlTemplateTokens[4];
        outStream.write(token5.data(),token5.size());

        outStream.write(url.data(),url.size());

        auto const& token6 = htmlTemplateTokens[4];
        outStream.write(token6.data(),token6.size());

        ///
        /// Read the tdf html and validate the data.
        ///

        XMLDocFreePtr xmlDoc { htmlReadFile(sampleTemplateOutput.data(), nullptr,
                                            HTML_PARSE_RECOVER | HTML_PARSE_NOWARNING |
                                            HTML_PARSE_NOERROR | HTML_PARSE_NODEFDTD |
                                            HTML_PARSE_NONET   | HTML_PARSE_NOIMPLIED) };

        if (!xmlDoc) {
            BOOST_FAIL(sampleTemplateOutput + " not parsed successfully.");
        }

        // Create xpath context
        XMLXPathContextFreePtr context { xmlXPathNewContext(xmlDoc.get()) };
        if (!context) {
            BOOST_FAIL(sampleTemplateOutput + " error in xmlXPathNewContext");
        }

        // Find the 'input' element with attribute 'id' = "data-input"
        const xmlChar *xpath = (xmlChar*) "//body/input";
        XMLXPathObjectFreePtr result { xmlXPathEvalExpression(xpath, context.get())};
        if (!result) {
            BOOST_FAIL(sampleTemplate + " error in xmlXPathEvalExpression");
        }

        if(xmlXPathNodeSetIsEmpty(result->nodesetval)) {
            BOOST_FAIL("<input> elements are missing");
        }

        xmlNodeSetPtr nodeset = result->nodesetval;
        for (int i = 0; i < nodeset->nodeNr; i++) {

            // input element.
            xmlNodePtr inputNode = nodeset->nodeTab[i];
            XMLCharFreePtr attributeValue { xmlGetProp(inputNode, reinterpret_cast<const xmlChar*>(kHTMLIdAttribute)) };

            // Check for "data-input"
            if (attributeValue && boost::iequals(kHTMLDataInput, (const char*)attributeValue.get())) {

                XMLCharFreePtr xmlCharBase64TDF { xmlGetProp(inputNode, reinterpret_cast<const xmlChar*>(kHTMLValueAttribute)) };
                if (!xmlCharBase64TDF) {
                    BOOST_FAIL("value attribute is missing");
                }

                std::string base64TDF(reinterpret_cast<const char*>(xmlCharBase64TDF.get()));
                BOOST_TEST(base64TDF == "SGVsbG8sIFdvcmxkIQ==");
            }

            // Check for "data-manifest"
            if (attributeValue && boost::iequals(kHTMLDataManifest, (const char*)attributeValue.get())) {

                XMLCharFreePtr xmlCharBase64Manifest{ xmlGetProp(inputNode, reinterpret_cast<const xmlChar*>(kHTMLValueAttribute)) };
                if (!xmlCharBase64Manifest) {
                    BOOST_FAIL("value attribute is missing");
                }

                std::string base64Manifest(reinterpret_cast<const char*>(xmlCharBase64Manifest.get()));
                BOOST_TEST(base64Manifest == "bWFuaWZlc3Q=");
            }
        }
    }

BOOST_AUTO_TEST_SUITE_END()
