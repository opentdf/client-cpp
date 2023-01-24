/*
* Copyright 2023 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
* Created by  Sujan Reddy on 1/18/23
*/

#include "rca_io_provider.h"
#include "logger.h"
#include "tdf_exception.h"
#include <iostream>
#include <fstream>
#include "tdf_constants.h"
#include "sdk_constants.h"
#include "network/http_service_provider.h"
#include "crypto/crypto_utils.h"
#include "utils.h"
#include "nlohmann/json.hpp"
#include <regex>
#include <boost/exception/diagnostic_information.hpp>

namespace virtru {

    constexpr auto kMaxBufferSize = 5 * 1024 * 1024;
    constexpr auto kThresholdBufferSize = 2 * 1024 * 1024;


    /// Constructor
    RCAInputProvider::RCAInputProvider(const std::string& url) :
            m_url{url} {
        LogTrace("RCAInputProvider::RCAInputProvider");

        m_httpServiceProvider = std::make_shared<network::HTTPServiceProvider>();
    }

    /// Read data of given length from the index and store into bytes buffer
    void RCAInputProvider::readBytes(size_t index, size_t length, WriteableBytes& bytes) {
        LogTrace("RCAInputProvider::readBytes");

        if (length == 0) {
            // nothing to do
            return;
        }

        if (bytes.size() < length) {
            std::string errorMsg{"Buffer not large enough for requested length"};
            LogError(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        unsigned status = kHTTPBadRequest;
        std::string netResponse;
        std::promise<void> netPromise;
        auto netFuture = netPromise.get_future();

        std::ostringstream ossRangeSpec;
        ossRangeSpec << "bytes=" << index << "-" << (index+length-1);
        std::string rangeSpec = ossRangeSpec.str();

        LogDebug("rangeSpec='" + rangeSpec + "'");

        m_headers = {{kRangeRequest, rangeSpec}, {kAcceptKey, kContentTypeOctetStream}};
        std::string content; // content is null for a get

        m_httpServiceProvider->executeGet(
                m_url, m_headers,
                [&netPromise, &netResponse, &status](
                        unsigned int statusCode, std::string &&response) {
                    status = statusCode;
                    netResponse = std::move(response);

                    netPromise.set_value();
                },
                "", "", "");

        netFuture.get();

        // Handle HTTP error.
        if ((status != kHTTPOk) && (status != kHTTPOkPartial)) {
            std::ostringstream oss;
            oss << "Network failed status: " << status << " response: " << netResponse;
            LogError(oss.str());
            ThrowException(oss.str(), VIRTRU_NETWORK_ERROR);
        }

        if (bytes.size() < netResponse.size()){
            std:: ostringstream oss;
            oss << "response size=" << netResponse.size() << " buffer size=" << bytes.size();
            LogError(oss.str());
            ThrowException(oss.str(), VIRTRU_SYSTEM_ERROR);
        }

        std::memcpy(bytes.data(), netResponse.data(), netResponse.size());
    };

    /// Return the size of provider
    size_t RCAInputProvider::getSize() {
        LogTrace("RCAInputProvider::getSize");

        unsigned status = kHTTPBadRequest;
        std::string netResponse;
        std::promise<void> netPromise;
        auto netFuture = netPromise.get_future();

        m_headers = {{"Connection", "close"}};
        std::string content; // content is null for a head

        m_httpServiceProvider->executeHead(
                m_url, m_headers,
                [&netPromise, &netResponse, &status](
                        unsigned int statusCode, std::string &&response) {
                    status = statusCode;
                    netResponse = std::move(response);
                    netPromise.set_value();
                },
                "", "", "");

        netFuture.get();

        // Handle HTTP error.
        if ((status != kHTTPOk) && (status != kHTTPOkPartial)) {
            std::ostringstream oss;
            oss << "Network failed status: " << status << " response: " << netResponse;
            LogError(oss.str());
            ThrowException(oss.str(), VIRTRU_NETWORK_ERROR);
        }

        size_t result = 0;
        const std::string kContentLengthKeyLower("content-length");
        //As per HTTP spec, header keys are not case sensitive.
        //This means some servers will send `content-length` and others will send `Content-Length`,
        //and we must accept both and treat them as the same thing. This makes a compelling case for using
        //an off the shelf header manip library - but we have no such luxury here.
        //
        //So, convert the entire response to lowercase (we only care about content-length anyway)
        //and then try to get our length value
        std::transform(netResponse.begin(), netResponse.end(), netResponse.begin(), ::tolower);
        auto vPos = netResponse.find(kContentLengthKeyLower);
        if (vPos != std::string::npos) {
            vPos += kContentLengthKeyLower.length() + 2; //value is beyond key and trailing ": "
            if (vPos >= netResponse.length()) {
                const char* csError = "No value found for Content-Length";
                LogError(csError);
                ThrowException(csError, VIRTRU_NETWORK_ERROR);
            }
            std::string ssContentLength = netResponse.substr(vPos);
            result = atol(ssContentLength.c_str());
        } else {
            std::ostringstream oss;
            oss << "Did not find Content-Length in response status: " << status << " response: " << netResponse;
            LogError(oss.str());
            ThrowException(oss.str(), VIRTRU_NETWORK_ERROR);
        }

        return result;
    }

    /// Replace the default network provider with the supplied one - used for unit test
    void RCAInputProvider::setHttpServiceProvider(std::shared_ptr<INetwork> httpServiceProvider) {
        LogTrace("S3InputProvider::setHttpServiceProvider");
        m_httpServiceProvider = std::move(httpServiceProvider);
    }
    /// Constructor
    RCAOutputProvider::RCAOutputProvider(const std::string& url, HttpHeaders headers) :
            m_url{url}, m_headers{headers} {
        LogTrace("RCAOutputProvider::RCAOutputProvider");

        m_httpServiceProvider = std::make_shared<network::HTTPServiceProvider>();
        m_buffer.resize(kMaxBufferSize);

        startRCAService();

        fetchNewRCALinks();
    }

    // Write the bytes to output provider
    void RCAOutputProvider::writeBytes(Bytes bytes) {
        LogTrace("FileOutputProvider::writeBytes");

        if (bytes.size() == 0) {
            // nothing to do
            return;
        }

        if (bytes.size() > kMaxBufferSize) {
            ThrowException("RCA buffer size not supported ", VIRTRU_SYSTEM_ERROR);
        }

        if (m_rcaLinks.empty()) {
            fetchNewRCALinks();
        }

        auto sizeLeftInBuffer = kMaxBufferSize - m_bufferSize;
        if (kMaxBufferSize >  m_bufferSize + bytes.size()) {
            // Copy the bytes to the buffer
            std::copy(bytes.begin(), bytes.end(),
                      m_buffer.begin() + m_bufferSize);
            m_bufferSize += bytes.size();
            return;
        }

        auto bytesToBeCopiedLater = bytes.size() - sizeLeftInBuffer;
        auto bytesToCopyNow =  bytes.size() - bytesToBeCopiedLater;

        // Copy the bytes to the buffer
        std::copy_n(bytes.begin(), bytesToCopyNow, m_buffer.begin() + m_bufferSize);
        m_bufferSize += bytesToCopyNow;

        // Copy the remaining bytes to extraBuffer
        std::vector<gsl::byte> extraBuffer(bytesToBeCopiedLater);
        std::copy(bytes.begin() + sizeLeftInBuffer, bytes.end(), extraBuffer.begin());

        copyDataToRemoteURL();

        // reset the buffer size
        m_bufferSize = 0;

        // Copy the data from extra buffer to working copy of the buffer
        std::copy(extraBuffer.begin() , extraBuffer.end(), m_buffer.begin());
        m_bufferSize += extraBuffer.size();
    }

    /// Copy data to remote url.
    void RCAOutputProvider::copyDataToRemoteURL() {

        if (m_bufferSize == 0) {
            return;
        }

        unsigned status = kHTTPBadRequest;
        std::string netResponse;
        std::promise<void> netPromise;
        auto netFuture = netPromise.get_future();

        auto url = m_rcaLinks.front();
        m_rcaLinks.pop();
        m_httpServiceProvider->executePut(
                url, {}, std::string(toChar(m_buffer.data()), m_bufferSize),
                [&netPromise, &netResponse, &status](
                        unsigned int statusCode, std::string &&response) {
                    status = statusCode;
                    netResponse = std::move(response);

                    netPromise.set_value();
                },
                "", "", "");

        netFuture.get();

        // Handle HTTP error.
        if ((status != kHTTPOk)) {
            std::ostringstream oss;
            oss << "Network failed status: " << status << " response: " << netResponse;
            LogError(oss.str());
            ThrowException(oss.str(), VIRTRU_NETWORK_ERROR);
        }

        auto responseHeaders = Utils::parseHeaders(netResponse);
        auto etag = responseHeaders[kRCAEtag];
        etag.erase(remove( etag.begin(), etag.end(), '\"' ), etag.end());

        m_etags.push_back(etag);
        std::cout << "Response ETag:" << etag << std::endl;
    }

    ///Finished uploading and stop the RCA service
    void RCAOutputProvider::finishRCAService() {

        std::string rcaServiceResponse;
        unsigned status = kHTTPBadRequest;
        std::promise<void> netPromise;
        auto netFuture = netPromise.get_future();

        nlohmann::json finishRCALinksRequestBody;
        finishRCALinksRequestBody["key"] =  m_generatedKey;
        finishRCALinksRequestBody[kUploadId] =  m_uploadId;

        // Add etags
        finishRCALinksRequestBody["parts"] = nlohmann::json::array();
        auto index = 1;
        for (auto& etag : m_etags) {
            nlohmann::json etagObj;
            etagObj[kRCAEtag] = etag;
            etagObj["PartNumber"] = index;
            finishRCALinksRequestBody["parts"].emplace_back(etagObj);
            index += 1;
        }

        auto finishRCALinksRequestBodyStr = to_string(finishRCALinksRequestBody);
        LogDebug(finishRCALinksRequestBodyStr);

        std::cout << "finishRCALinksRequestBodyStr:" << finishRCALinksRequestBodyStr << std::endl;

        LogTrace("RCAOutputProvider::fetchNewRCALinks");
        auto url = m_url + kRCAFinish;
        m_httpServiceProvider->executePost(url, m_headers, to_string(finishRCALinksRequestBody),
                                           [&netPromise, &rcaServiceResponse, &status](unsigned int statusCode, std::string &&response) {
                                               status = statusCode;
                                               rcaServiceResponse = response;
                                               netPromise.set_value();
                                           },"", "","");

        netFuture.get();

        // Handle HTTP error.
        if (!Utils::goodHttpStatus(status)) {
            std::string exceptionMsg = "rca-link-service links failed status:";
            exceptionMsg += std::to_string(status);
            exceptionMsg += " - ";
            exceptionMsg += rcaServiceResponse;
            ThrowException(std::move(exceptionMsg), VIRTRU_NETWORK_ERROR);
        }

        LogDebug(rcaServiceResponse);
    }

    void RCAOutputProvider::flush() {

        // Clear any data in buffers
        copyDataToRemoteURL();

        // Finish the service.
        finishRCAService();
    }

    /// Replace the default network provider with the supplied one - used for unit test
    void RCAOutputProvider::setHttpServiceProvider(std::shared_ptr<INetwork> httpServiceProvider) {
        LogTrace("RCAOutputProvider::setHttpServiceProvider");
        m_httpServiceProvider = std::move(httpServiceProvider);
    }


    /// Start the RCA service
    void RCAOutputProvider::startRCAService() {

        std::string rcaServiceResponse;
        unsigned status = kHTTPBadRequest;
        std::promise<void> netPromise;
        auto netFuture = netPromise.get_future();

        LogTrace("RCAOutputProvider::startRCAService");
        auto url = m_url + kRCACreate;
        m_httpServiceProvider->executeGet(url, m_headers,
                                          [&netPromise, &rcaServiceResponse, &status](unsigned int statusCode, std::string &&response) {
                                              status = statusCode;
                                              rcaServiceResponse = response;
                                              netPromise.set_value();
                                          },"", "","");

        netFuture.get();

        // Handle HTTP error.
        if (!Utils::goodHttpStatus(status)) {
            std::string exceptionMsg = "rca-link-service create failed status:";
            exceptionMsg += std::to_string(status);
            exceptionMsg += " - ";
            exceptionMsg += rcaServiceResponse;
            ThrowException(std::move(exceptionMsg), VIRTRU_NETWORK_ERROR);
        }

        LogDebug(rcaServiceResponse);
        nlohmann::json rcaServiceResponseObj;
        try{
            rcaServiceResponseObj = nlohmann::json::parse(rcaServiceResponse);
        } catch (...){
            if (rcaServiceResponseObj == ""){
                ThrowException("No response from rca/create service", VIRTRU_NETWORK_ERROR);
            }
            else{
                ThrowException("Could not parse rca/create service response: " + boost::current_exception_diagnostic_information() + "  with response: ", VIRTRU_NETWORK_ERROR);
            }
        }

        m_uploadId = rcaServiceResponseObj[kUploadId];
        m_generatedKey = rcaServiceResponseObj[kGeneratedKey];

        std::cout << "UploadId:" << m_uploadId << std::endl;
        std::cout << "m_generatedKey:" << m_generatedKey << std::endl;
    }

    /// Fetch the new links
    void RCAOutputProvider::fetchNewRCALinks() {

        std::string rcaServiceResponse;
        unsigned status = kHTTPBadRequest;
        std::promise<void> netPromise;
        auto netFuture = netPromise.get_future();


        nlohmann::json fetchRCALinksRequestBody;
        fetchRCALinksRequestBody[kRCALinkServiceKey] =  m_generatedKey;
        fetchRCALinksRequestBody[kUploadId] =  m_uploadId;
        fetchRCALinksRequestBody[kPartNumber] =  m_nextPartNumber ;

        auto fetchRCALinksRequestBodyStr = to_string(fetchRCALinksRequestBody);
        LogDebug(fetchRCALinksRequestBodyStr);

        LogTrace("RCAOutputProvider::fetchNewRCALinks");
        auto url = m_url + kRCALinks;
        m_httpServiceProvider->executePost(url, m_headers, to_string(fetchRCALinksRequestBody),
                                          [&netPromise, &rcaServiceResponse, &status](unsigned int statusCode, std::string &&response) {
                                              status = statusCode;
                                              rcaServiceResponse = response;
                                              netPromise.set_value();
                                          },"", "","");

        netFuture.get();

        // Handle HTTP error.
        if (!Utils::goodHttpStatus(status)) {
            std::string exceptionMsg = "rca-link-service links failed status:";
            exceptionMsg += std::to_string(status);
            exceptionMsg += " - ";
            exceptionMsg += rcaServiceResponse;
            ThrowException(std::move(exceptionMsg), VIRTRU_NETWORK_ERROR);
        }

        LogDebug(rcaServiceResponse);
        nlohmann::json rcaServiceResponseObj;
        try{
            rcaServiceResponseObj = nlohmann::json::parse(rcaServiceResponse);
        } catch (...){
            if (rcaServiceResponseObj == ""){
                ThrowException("No response from rca/links service", VIRTRU_NETWORK_ERROR);
            }
            else{
                ThrowException("Could not parse rca/links service response: " + boost::current_exception_diagnostic_information() + "  with response: ", VIRTRU_NETWORK_ERROR);
            }
        }

        auto storageLinks = rcaServiceResponseObj["links"];
        for (auto& link : storageLinks) {
            std::string url = link["URL"];
            m_rcaLinks.push(url);
        }

        m_nextPartNumber += m_rcaLinks.size();
    }
}
