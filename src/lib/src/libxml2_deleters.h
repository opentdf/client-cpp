/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/06/11.
//

#ifndef VIRTRU_LIBXML2_DELETERS_H
#define VIRTRU_LIBXML2_DELETERS_H

#include <memory>
#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>
#include <libxml/xpath.h>
#include <libxml/xmlsave.h>
#include <libxml/parser.h>
#include <libxml/xmlwriter.h>
#include <libxml/tree.h>
#include <libxml/xmlschemas.h>
#include <libxml/xmlreader.h>

namespace virtru {

    struct XMLDocDeleter { void operator()(xmlDoc* doc) {::xmlFreeDoc(doc);} };
    using XMLDocFreePtr = std::unique_ptr<xmlDoc, XMLDocDeleter>;

    struct XMLXPathContextDeleter { void operator()(xmlXPathContext* context) {::xmlXPathFreeContext(context);} };
    using XMLXPathContextFreePtr = std::unique_ptr<xmlXPathContext, XMLXPathContextDeleter>;

    struct XMLXPathObjectDeleter { void operator()(xmlXPathObject* object) {::xmlXPathFreeObject(object);} };
    using XMLXPathObjectFreePtr = std::unique_ptr<xmlXPathObject, XMLXPathObjectDeleter>;

    struct XMLCharDeleter { void operator()(xmlChar* xml) {::xmlFree(xml);} };
    using XMLCharFreePtr = std::unique_ptr<xmlChar, XMLCharDeleter>;

    struct xmlTextWriterDelete { void operator()(xmlTextWriter* writer) {::xmlFreeTextWriter(writer);} };
    using xmlTextWriterFreePtr = std::unique_ptr<xmlTextWriter, xmlTextWriterDelete>;

    struct XMLBufferDelete { void operator()(xmlBuffer* buffer) {::xmlBufferFree(buffer);} };
    using xmlBufferFreePtr = std::unique_ptr<xmlBuffer, XMLBufferDelete>;

    struct XmlCharDeleter { void operator()(xmlChar* xmlCharPtr) { xmlFree(xmlCharPtr); } };
    using XmlCharFreePtr = std::unique_ptr<xmlChar, XmlCharDeleter>;

    struct XmlDocDeleter { void operator()(xmlDoc* doc) { xmlFreeDoc(doc); } };
    using XmlDocFreePtr = std::unique_ptr<xmlDoc, XmlDocDeleter>;

    struct XmlXPathObjectDeleter { void operator()(xmlXPathObject* xmlPath) { xmlXPathFreeObject(xmlPath); } };
    using XmlXPathObjectFreePtr = std::unique_ptr<xmlXPathObject, XmlXPathObjectDeleter>;

    struct XmlSchemaDeleter { void operator()(xmlSchema* schema) {::xmlSchemaFree(schema);} };
    using XmlSchemaFreePtr = std::unique_ptr<xmlSchema, XmlSchemaDeleter>;

    struct XmlSchemaValidCtxtDeleter { void operator()(xmlSchemaValidCtxt* ctxt) {::xmlSchemaFreeValidCtxt(ctxt);} };
    using XmlSchemaValidCtxtFreePtr = std::unique_ptr<xmlSchemaValidCtxt, XmlSchemaValidCtxtDeleter>;

    struct XmlSchemaParserCtxtDeleter { void operator()(xmlSchemaParserCtxt* ctxt) {::xmlSchemaFreeParserCtxt(ctxt);} };
    using XmlSchemaParserCtxtFreePtr = std::unique_ptr<xmlSchemaParserCtxt, XmlSchemaParserCtxtDeleter>;

    struct XmlTextReaderDeleter { void operator()(xmlTextReader* reader) {::xmlFreeTextReader(reader);} };
    using XmlTextReaderFreePtr = std::unique_ptr<xmlTextReader, XmlTextReaderDeleter>;

}  // namespace virtru

#endif //VIRTRU_LIBXML2_DELETERS_H
