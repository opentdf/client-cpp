/*
 * Copyright 2021 Virtru Corporation
 *
 * SPDX - License Identifier: BSD-3-Clause-Clear
 *
 */
//
//  TDF SDK
//
//

#ifndef MOCK_NETWORK_INTERFACE_H_
#define MOCK_NETWORK_INTERFACE_H_

#include "map"
#include "tuple"
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include "network_interface.h"
#include "numeric"
#include <boost/functional/hash.hpp>

namespace virtru {

    using HttpHeaders = std::unordered_map<std::string, std::string>;

    // callback once the http request is completed.
    using HTTPServiceCallback = std::function<void(unsigned int statusCode, std::string &&response)>;

    class MockNetwork : public INetwork {
        private:
            typedef std::tuple<std::string, unsigned int> responseMock;

            struct RequestMatcher {
                std::string url;
                HttpHeaders headers;

                bool operator==(const RequestMatcher &other) const {
                    return (url == other.url &&
                            headers == other.headers);
                }
            };

            struct RequestMatcherHasher
            {
                std::size_t operator()(const RequestMatcher& k) const
                {
                    using std::size_t;
                    using std::hash;
                    using std::string;
                    boost::hash<HttpHeaders::value_type> elem_hash;
                    auto combine = [&](size_t acc, HttpHeaders::const_reference elem){ return acc ^ elem_hash(elem); };
                    auto headerHash = std::accumulate(k.headers.begin(), k.headers.end(), 0, combine);

                    return ((hash<string>()(k.url)
                             ^ headerHash) >> 1);
                }
            };

            std::unordered_map<RequestMatcher, responseMock, RequestMatcherHasher> GETExpectations;
            std::unordered_map<RequestMatcher, responseMock, RequestMatcherHasher> POSTExpectations;


        public: //INetwork members
            virtual void executeGet(const std::string &url, const HttpHeaders &headers, HTTPServiceCallback &&callback, const std::string&, const std::string&, const std::string&) override;
            virtual void executePost(const std::string &url, const HttpHeaders &headers,
                                     std::string &&body, HTTPServiceCallback &&callback, const std::string&, const std::string&, const std::string&) override;
            virtual void executePatch(const std::string &url, const HttpHeaders &headers,
                                      std::string &&body, HTTPServiceCallback &&callback, const std::string&, const std::string&, const std::string&) override;

        public:
            typedef std::tuple<const std::string, const std::string, const HttpHeaders> recordedResponse;

            void addGETExpectation(const std::string &expectedUrl, const HttpHeaders &expectedHeaders, const std::string &mockResponse, unsigned int mockStatusCode);
            void addPOSTExpectation(const std::string &expectedUrl, const HttpHeaders &expectedHeaders, const std::string &mockResponse, unsigned int mockStatusCode);

            //Thingie to hold requests we get (and their bodies)
            std::vector<recordedResponse> RecordedPOSTCalls;
            std::function<std::string(std::string)> POSTTransformer = 0;
    };
}
#endif // MOCK_NETWORK_INTERFACE_H_
