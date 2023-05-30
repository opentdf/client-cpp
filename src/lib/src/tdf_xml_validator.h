//
// Created by Patrick Mancuso on 5/30/23.
//

#ifndef OPENTDF_CLIENT_TDF_XML_VALIDATOR_H
#define OPENTDF_CLIENT_TDF_XML_VALIDATOR_H

#include <libxml/xmlreader.h>

namespace virtru {

    class TDFXMLValidator {
      public:
        /// Validate input XML against supplied schema
        /// \param schemafile - name of file containing XSD schema
        TDFXMLValidator(const char *schema);

        /// destructor
        ~TDFXMLValidator();

        /// Verify that the supplied schema loaded without errors
        bool isSchemaValid();

        /// Validate input XML against supplied schema
        /// \param xmlfile - name of file containing XML data
        bool validateXML(const char *xmlfile);

        /// Validate input XML against supplied schema
        /// \param reader - pointer to reader for input XML
        bool validateXML(xmlTextReaderPtr reader);

        /// Validate input XML against supplied schema
        /// \param doc - XML document node ptr
        bool validateXML(xmlDocPtr doc);

      private:
        xmlSchemaValidCtxtPtr m_valid_ctxt;
    };
}

#endif // OPENTDF_CLIENT_TDF_XML_VALIDATOR_H
