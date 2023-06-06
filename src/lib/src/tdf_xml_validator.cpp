/*
* Copyright 2023 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
 */
//
// Created by Patrick Mancuso on 5/30/23.
//

#include "tdf_xml_validator.h"
#include "tdf_exception.h"
#include "logger.h"
#include <string>
#include <sstream>

using namespace virtru;

// Based on https://stackoverflow.com/questions/54124989/libxml2-get-xsd-validation-errors

// This routine is a callback for the parser, used when there is an error validating the supplied XML against the schema
static void schemaParseErrorHandler(void *arg, xmlErrorPtr error)
{
    std::ostringstream errorMsg;

    errorMsg << "Schema validation error " << error->file << "(" << error->line << ") " << error->int2 << " " << error->code << " " << error->message;
    LogError(errorMsg.str());
    *((bool*)arg) = true;
}

TDFXMLValidator::TDFXMLValidator() {
    m_valid_ctxt = nullptr;
    m_schemaInitialized = false;
}

bool TDFXMLValidator::setSchema(const std::string& schemafile) {
    xmlSchemaPtr schema = nullptr;
    xmlSchemaParserCtxtPtr schema_parser_ctxt = nullptr;
    m_valid_ctxt = nullptr;
    m_schemaInitialized = true;

    xmlInitParser();

    if ((schema_parser_ctxt = xmlSchemaNewParserCtxt(schemafile.c_str())))
    {
        schema = xmlSchemaParse(schema_parser_ctxt);
        xmlSchemaFreeParserCtxt(schema_parser_ctxt);
        if (schema)
        {
            m_valid_ctxt = xmlSchemaNewValidCtxt(schema);
        }
    }
    return isSchemaValid();
}

TDFXMLValidator::~TDFXMLValidator() {
    xmlCleanupParser();
}

/// Verify that the supplied schema loaded without errors
bool TDFXMLValidator::isSchemaValid() {
    if (m_valid_ctxt)
        return true;
    else
        return false;
}

bool TDFXMLValidator::validate(const std::string &xmlfile) {
    xmlTextReaderPtr reader = 0;
    bool retval = false;

    reader = xmlReaderForFile(xmlfile.c_str(), 0, 0);
    retval = validate(reader);
    xmlFreeTextReader(reader);

    return retval;
}

bool TDFXMLValidator::validate(xmlDoc* doc) {
    xmlTextReaderPtr reader = 0;
    bool retval = false;

    reader = xmlReaderWalker(doc);
    retval = validate(reader);
    xmlFreeTextReader(reader);

    return retval;
}

bool TDFXMLValidator::validate(xmlTextReaderPtr reader) {
    bool retval = false;
    int has_schema_errors = 0;
    int moreToRead = -1;

    // Default: no setSchema done, no schema loaded, nothing to validate against, return pass for this xml
    if (m_schemaInitialized == false) {
        retval = true;
    } else {
        // Otherwise:  If a setSchema was attempted, use it
        if (!m_valid_ctxt) {
            // The setSchema failed, so return fail result for this xml
            retval = false;
        } else {
            // A setSchema succeeded, use it to validate this xml
            if (reader) {
                xmlTextReaderSchemaValidateCtxt(reader, m_valid_ctxt, 0);
                xmlSchemaSetValidStructuredErrors(m_valid_ctxt, schemaParseErrorHandler, &has_schema_errors);

                // Returns 1 if more to read, 0 if successfully completed reading, other values indicate errors
                moreToRead = xmlTextReaderRead(reader);

                while (moreToRead == 1 && !has_schema_errors) {
                    moreToRead = xmlTextReaderRead(reader);
                }

                if (moreToRead != 0) {
                    // There was an error parsing the supplied XML
                    xmlErrorPtr error = xmlGetLastError();
                    std::ostringstream errorMsg;
                    errorMsg << "Schema validation error " << error->file << "(" << error->line << ") " << error->int2 << " " << error->code << " " << error->message;
                    ThrowException(errorMsg.str(), VIRTRU_TDF_FORMAT_ERROR);
                    retval = false;
                } else {
                    retval = true;
                }
            }
        }
    }
    return retval;
}