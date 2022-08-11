/*
 * Copyright 2021 Virtru Corporation
 *
 * SPDX - License Identifier: BSD-3-Clause-Clear
 *
 */
//
//  TDF SDK
//


#include "map"
#include <iostream>
#include "numeric"
#include "mock_network_interface.h"
#include "tuple"
#include "nlohmann/json.hpp"
#include "sdk_constants.h"
#include "logger.h"

namespace virtru {

    using TDFDataSinkCb = std::function < Status(BufferSpan)>;
    void MockNetwork::executeGet(const std::string &url, const HttpHeaders &headers, HTTPServiceCallback &&callback, const std::string &/*certAuth*/, const std::string &/*clientKeyFileName*/, const std::string &/*clientCertFileName*/) {
        auto result = GETExpectations.find({url, headers});
        if (GETExpectations.end() != result)
        {
            std::cout << "Matched GET mock: " << result->first.url;
            auto matchedMock = result->second;
            callback(std::get<1>(matchedMock), move(std::get<0>(matchedMock)));
        } else {
            callback(69, "Didn't match mock");
        }
    };
    void MockNetwork::executePost(const std::string &url, const HttpHeaders &headers, [[maybe_unused]] std::string &&body, HTTPServiceCallback &&callback, const std::string &/*certAuth*/, const std::string &/*clientKeyFileName*/, const std::string &/*clientCertFileName*/) {
        auto result = POSTExpectations.find({url, headers});
        std::cout << "Trying to match against URL: " << url << std::endl;
        std::cout << "Trying to match against Headers: ";
        for (auto const &pair: headers) {
            std::cout << "{" << pair.first << ": " << pair.second << "}\n";
        }
        if (POSTExpectations.end() != result)
        {
            std::cout << "Matched POST mock: " << result->first.url << std::endl;

            RecordedPOSTCalls.emplace_back(url, body, headers);
            auto matchedMock = result->second;
            if (POSTTransformer != 0 && std::get<0>(matchedMock).empty()) {
                auto transformedBody = POSTTransformer(body);
                std::cout << "Transformed POST body: " << transformedBody << std::endl;
                callback(std::get<1>(matchedMock), move(transformedBody));
            } else {
                callback(std::get<1>(matchedMock), move(std::get<0>(matchedMock)));
            }
        } else {
            callback(69, "Didn't match mock");
        }
    };

    // Avoid unreferenced parm warning by not supplying names for the parms
    void MockNetwork::executePatch(const std::string &/*url*/, const HttpHeaders &/*headers*/,
                                   std::string &&/*body*/, HTTPServiceCallback &&/*callback*/, const std::string &/*certAuth*/, const std::string &/*clientKeyFileName*/, const std::string &/*clientCertFileName*/) {
    };


    void MockNetwork::addGETExpectation(const std::string &expectedUrl, const HttpHeaders &expectedHeaders, const std::string &mockResponse, unsigned int mockStatusCode) {
        auto mockRes = std::make_tuple(mockResponse, mockStatusCode);
        GETExpectations.insert_or_assign({expectedUrl, expectedHeaders}, mockRes);
    };

    void MockNetwork::addPOSTExpectation(
        const std::string &expectedUrl,
        const HttpHeaders &expectedHeaders,
        const std::string &mockResponse,
        unsigned int mockStatusCode
    ) {
        std::cout << "Adding expectation for POST" << expectedUrl << std::endl;
        auto mockRes = std::make_tuple(mockResponse, mockStatusCode);
        POSTExpectations.insert_or_assign({expectedUrl, expectedHeaders}, mockRes);
    };
}; // namespace virtru
