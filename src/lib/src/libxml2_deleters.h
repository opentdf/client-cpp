/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License - Identifier: MIT
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

}  // namespace virtru

#endif //VIRTRU_LIBXML2_DELETERS_H
