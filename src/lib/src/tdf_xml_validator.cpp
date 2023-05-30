//
// Created by Patrick Mancuso on 5/30/23.
//

#include "tdf_xml_validator.h"

using namespace virtru;

// Based on https://stackoverflow.com/questions/54124989/libxml2-get-xsd-validation-errors
static void schemaParseErrorHandler(void *arg, xmlErrorPtr error)
{
    fprintf(stderr, "Error at line %d, column %d\n%s", error->line, error->int2, error->message);
    *((bool*)arg) = true;
}

TDFXMLValidator::TDFXMLValidator(const char *schemafile) {
    xmlSchemaPtr schema = 0;
    xmlSchemaParserCtxtPtr schema_parser_ctxt = 0;
    m_valid_ctxt = 0;

    xmlInitParser();

    if ((schema_parser_ctxt = xmlSchemaNewParserCtxt(schemafile)))
    {
        schema = xmlSchemaParse(schema_parser_ctxt);
        xmlSchemaFreeParserCtxt(schema_parser_ctxt);
        if (schema)
        {
            m_valid_ctxt = xmlSchemaNewValidCtxt(schema);
        }
    }
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

bool TDFXMLValidator::validateXML(const char *xmlfile) {
    xmlTextReaderPtr reader = 0;
    bool retval = false;

    reader = xmlReaderForFile(xmlfile, 0, 0);
    retval = validateXML(reader);
    xmlFreeTextReader(reader);

    return retval;
}

bool TDFXMLValidator::validateXML(xmlDoc* doc) {
    xmlTextReaderPtr reader = 0;
    bool retval = false;

    reader = xmlReaderWalker(doc);
    retval = validateXML(reader);
    xmlFreeTextReader(reader);

    return retval;
}

bool TDFXMLValidator::validateXML(xmlTextReaderPtr reader) {
    bool retval = false;
    int has_schema_errors = 0;
    int ret = -1;

    if (m_valid_ctxt) {
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
    } else {
        // No valid schema context
        retval = false;
    }
    return retval;
}