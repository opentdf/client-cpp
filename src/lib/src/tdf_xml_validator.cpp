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
#include <string>

using namespace virtru;

// Based on https://stackoverflow.com/questions/54124989/libxml2-get-xsd-validation-errors
static void schemaParseErrorHandler(void *arg, xmlErrorPtr error)
{
    fprintf(stderr, "Error at line %d, column %d\n%s", error->line, error->int2, error->message);
    *((bool*)arg) = true;
}

TDFXMLValidator::TDFXMLValidator() {
    m_valid_ctxt = 0;
    m_schemaInitialized = false;
}

bool TDFXMLValidator::setSchema(const std::string& schemafile) {
    xmlSchemaPtr schema = 0;
    xmlSchemaParserCtxtPtr schema_parser_ctxt = 0;
    m_valid_ctxt = 0;
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
    int ret = -1;

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

                ret = xmlTextReaderRead(reader);

                while (ret == 1 && !has_schema_errors) {
                    ret = xmlTextReaderRead(reader);
                }

                if (ret != 0) {
                    xmlErrorPtr err = xmlGetLastError();
                    fprintf(stdout, "%s: failed to parse in line %d, col %d. Error %d: %s\n", err->file, err->line, err->int2, err->code, err->message);
                    retval = false;
                } else {
                    retval = true;
                }
            }
        }
    }
    return retval;
}