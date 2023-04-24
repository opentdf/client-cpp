/*
 * Copyright 2023 Virtru Corporation
 *
 * SPDX - License Identifier: BSD-3-Clause-Clear
 *
 */
//
// Created by Patrick Mancuso on 3/28/23.
//

#ifndef ICTDF_H
#define ICTDF_H

#include "libxml/xmlschemas.h"
#include <string>

namespace virtru {
    class Ictdf {

      xmlSchemaParserCtxtPtr m_parser_ctxt = 0;
      xmlSchemaPtr m_schema = 0;
      xmlSchemaValidCtxtPtr m_schemaValidationContext = 0;

      public:
        Ictdf();
        ~Ictdf();
        bool parseFile(std::string& xmlFileName);
    };
}

#endif // ICTDF_H
