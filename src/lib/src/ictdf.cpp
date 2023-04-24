/*
* Copyright 2023 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
// Created by Patrick Mancuso on 3/28/23.
//


#include "ictdf.h"
#define LIBXML_READER_ENABLED 1
#include "libxml/xmlschemas.h"
#include "libxml/xmlreader.h"

#include <string>
#include <iostream>

namespace virtru {

    Ictdf::Ictdf() {

        std::string schema_filename_str = "IC-TDF/Schema/IC-TDF/IC-TDF.xsd";
        const auto *schema_filename = schema_filename_str.c_str();

        // schema parser ptr
        m_parser_ctxt = xmlSchemaNewParserCtxt(schema_filename);

        if (!m_parser_ctxt) {
            std::cout << "create of schema parser context failed for " << schema_filename << std::endl;
        }

        // schema parser
        m_schema = xmlSchemaParse(m_parser_ctxt);

        //xmlSchemaPtr parsedSchema = nullptr;
        //xmlSchemaSetParserStructuredErrors(m_parser_ctxt, ProcessParsingError, nullptr);

        //xmlSchemaFreeParserCtxt(m_parser_ctxt);

        if (m_schema) {
            std::cout << "creating schemaValidationContext" << std::endl;
            m_schemaValidationContext = xmlSchemaNewValidCtxt(m_schema);
        }
    }

    Ictdf::~Ictdf()
    {
        xmlSchemaFree(m_schema);
    }

    bool Ictdf::parseFile(std::string& xmlFilename)
    {

        // read the xml file
#if 0
        xmlDocPtr xmlTextReader = xmlReadFile(xmlFilename.c_str(), NULL, XML_PARSE_DTDVALID);
        if (xmlTextReader == nullptr)
        {
            //F1_ERROR("Failed to open '{0}'.", xmlFilename);
            return false; // failed to read xml file...
        }
#endif
        // configure schema validation
        int hasSchemeErrors = 0;
        xmlTextReaderPtr xmlTextReader = xmlNewTextReaderFilename(xmlFilename.c_str());
        xmlTextReaderSchemaValidateCtxt(xmlTextReader, m_schemaValidationContext, 0);
        //xmlSchemaSetValidStructuredErrors(schemaValidationContext, ProcessValidatorError, &hasSchemeErrors);

        // process the xml file
        int hasValidationErrors = 0;
        do
        {
            hasValidationErrors = xmlTextReaderRead(xmlTextReader);

            std::cout << "hasValidationErrors=" << hasValidationErrors << std::endl;
        } while (hasValidationErrors == 1 && !hasSchemeErrors);
        
        // free up the text reader memory
        //xmlFreeTextReader(xmlTextReader);

    }
}
