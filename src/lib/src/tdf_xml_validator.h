/*
* Copyright 2023 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
 */
//
// Created by Patrick Mancuso on 5/30/23.
//

#ifndef OPENTDF_CLIENT_TDF_XML_VALIDATOR_H
#define OPENTDF_CLIENT_TDF_XML_VALIDATOR_H

#include "libxml2_deleters.h"
#include "libxml/xmlreader.h"
#include <string>

namespace virtru {

    class TDFXMLValidator {
      public:
        /// constructor
        TDFXMLValidator();

        /// destructor
        ~TDFXMLValidator();

        /// Validate input XML against supplied schema.  Required for validation.
        /// NOTE: If no setSchema call is made, no validation is performed by any of the following methods.
        /// \param schema - URL or name of file containing XSD schema
        bool setSchema(const std::string& schema);

        /// Verify that the supplied schema loaded without errors
        bool isSchemaValid();

        /// Validate input XML against supplied schema
        /// \param xmlfile - name of file containing XML data
        bool validate(const std::string &xmlfile);

        /// Validate input XML against supplied schema
        /// \param reader - pointer to reader for input XML
        bool validate(xmlTextReaderPtr reader);

        /// Validate input XML against supplied schema
        /// \param doc - XML document node ptr
        bool validate(xmlDocPtr doc);

      private:
        bool m_schemaInitialized;
        XmlSchemaFreePtr m_schema;
        XmlSchemaValidCtxtFreePtr m_valid_ctxt;
    };
}

#endif // OPENTDF_CLIENT_TDF_XML_VALIDATOR_H
