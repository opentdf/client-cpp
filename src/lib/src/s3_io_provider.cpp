/*
* Copyright 2022 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
* Created by Patrick Mancuso on 5/3/22.
*/

#include "s3_io_provider.h"
#include "logger.h"
#include "tdf_exception.h"
#include <iostream>
#include <fstream>
#include "tdf_constants.h"
#include "sdk_constants.h"
#include "network/http_service_provider.h"
#include "crypto/crypto_utils.h"
#include <regex>

namespace virtru {

    S3InputProvider::S3InputProvider(const std::string& url, const std::string& awsAccessKeyId, const std::string& awsSecretAccessKey, const std::string& awsRegionName) :
                                        m_url{url}, m_awsAccessKeyId{awsAccessKeyId}, m_awsSecretAccessKey{awsSecretAccessKey}, m_awsRegionName{awsRegionName} {
        LogTrace("S3InputProvider::S3InputProvider");

        m_httpServiceProvider = std::make_shared<network::HTTPServiceProvider>();
    }

    void S3InputProvider::readBytes(size_t index, size_t length, WriteableBytes& bytes) {
        LogTrace("S3InputProvider::readBytes");

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

        S3Utilities::signHeaders(kHttpGet, m_headers, m_url, content, m_awsAccessKeyId, m_awsSecretAccessKey, m_awsRegionName);

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

    size_t S3InputProvider::getSize() {
        LogTrace("FileOutputProvider::getSize");

        unsigned status = kHTTPBadRequest;
        std::string netResponse;
        std::promise<void> netPromise;
        auto netFuture = netPromise.get_future();

        m_headers = {{"Connection", "close"}};
        std::string content; // content is null for a head

        S3Utilities::signHeaders(kHttpHead, m_headers, m_url, content, m_awsAccessKeyId, m_awsSecretAccessKey, m_awsRegionName);

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
        const std::string kContentLengthKey("Content-Length");
        const std::string kContentLengthKeyLower("content-length");
        //As per HTTP spec, header keys are not case sensitive.
        //This means some servers will send `content-length` and others will send `Content-Length`,
        //and we must accept both and treat them as the same thing. This makes a compelling case for using
        //an off the shelf header manip library - but we have no such luxury here, so:
        //
        //1. First try to match with mixed case
        //2. Then try to match with lowercase
        //3. Then give up if neither works
        //
        //There is probably a more concise way to do this.
        auto vPos = netResponse.find(kContentLengthKey);
        if (vPos == std::string::npos) {
            //We didn't find with mixed case, try again with lower
            vPos = netResponse.find(kContentLengthKeyLower);
        }
        if (vPos != std::string::npos) {
            vPos += kContentLengthKey.length() + 2; //value is beyond key and trailing ": "
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

    void S3InputProvider::setHttpServiceProvider(std::shared_ptr<INetwork> httpServiceProvider) {
        LogTrace("S3InputProvider::setHttpServiceProvider");
        m_httpServiceProvider = std::move(httpServiceProvider);
    }

    void S3OutputProvider::setHttpServiceProvider(std::shared_ptr<INetwork> httpServiceProvider) {
        LogTrace("S3OutputProvider::setHttpServiceProvider");
        m_httpServiceProvider = std::move(httpServiceProvider);
    }

    S3OutputProvider::S3OutputProvider(const std::string& url, const std::string& awsAccessKeyId, const std::string& awsSecretAccessKey, const std::string& awsRegionName) :
            m_url{url}, m_awsAccessKeyId{awsAccessKeyId}, m_awsSecretAccessKey{awsSecretAccessKey}, m_awsRegionName{awsRegionName} {
        LogTrace("S3OutputProvider::S3OutputProvider");

        m_httpServiceProvider = std::make_shared<network::HTTPServiceProvider>();
    }

    void S3OutputProvider::writeBytes(Bytes bytes) {
        LogTrace("FileOutputProvider::writeBytes");

        if (bytes.size() == 0) {
            // nothing to do
            return;
        }

        unsigned status = kHTTPBadRequest;
        std::string netResponse;
        std::promise<void> netPromise;
        auto netFuture = netPromise.get_future();

        m_headers = {{kAcceptKey, kContentTypeOctetStream}};

        S3Utilities::signHeaders(kHttpPut, m_headers, m_url, std::string(toChar(bytes.data()), bytes.size()), m_awsAccessKeyId, m_awsSecretAccessKey, m_awsRegionName);

        m_httpServiceProvider->executePut(
                m_url, m_headers, std::string(toChar(bytes.data()), bytes.size()),
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
    };

    std::string S3Utilities::generateAwsSignature(const std::string& secret, const std::string& date, const std::string& region, const std::string& service, const std::string& request, const std::string& toSign)
    {
        LogTrace("GenerateSigningSignature");
        std::string retval;

        // Calculate signing key
        auto dateHash = hmacSha256(toBytes(date), toBytes(secret));

        auto regionHash = hmacSha256(toBytes(region), dateHash);

        auto serviceHash = hmacSha256(toBytes(service), regionHash);

        auto signingKey = hmacSha256(toBytes(request), serviceHash);

        // Use signing key on supplied data to create signature
        auto signature = hmacSha256(toBytes(toSign), signingKey);

        // Take final result and hex encode to prepare for send
        retval =  hex(signature);

        return retval;
    }

// Sign the headers based on the provided information.
// Examples of correctly signed requests:
/*------ EXAMPLE BEGIN
PUT /pattest.html HTTP/1.1
User-Agent: aws-sdk-nodejs/2.585.0 linux/v8.10.0 callback
Content-Type: application/octet-stream
X-Amz-Content-Sha256: 932f3c1b56257ce8539ac269d7aab42550dacf8818d075f0bdf1990562aae3ef
Content-Length: 9
Host: h3-poc.s3.us-west-2.amazonaws.com
X-Amz-Date: 20191213T165015Z
Authorization: AWS4-HMAC-SHA256 Credential=AKIAWM2OYTV3QKEQ455I/20191213/us-west-2/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=16ae12a3e88c85a63f1476afb2f0886d708f6758316aae28b889a7a40df44941
Connection: close

123123123
-------- EXAMPLE END */
/*------ EXAMPLE BEGIN
GET
/
Action=ListUsers&Version=2010-05-08
content-type:application/x-www-form-urlencoded; charset=utf-8
host:iam.amazonaws.com
x-amz-date:20150830T123600Z

content-type;host;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
-------- EXAMPLE END */

    void S3Utilities::signHeaders(const char* httpVerb, HttpHeaders& headers, std::string url, std::string content, std::string awsAccessKeyId, std::string awsSecretAccessKey, std::string awsRegionName) {
        LogTrace("S3InputProvider::signHeaders");

        // For debug output
        std::ostringstream oss;

        // Calculate new signature

        // Secret (AWS4<secret access key>)
        std::string ssSecret = "AWS4";
        ssSecret.append(awsSecretAccessKey);

        // amazon date (20150830T123600Z)
        std::ostringstream osAmzDate;
        std::time_t now_time_t = std::time(nullptr);
        std::tm now_tm = *std::gmtime(&now_time_t);
        osAmzDate << std::put_time(&now_tm, "%Y%m%dT%H%M%SZ");
        std::string ssAmzDate = osAmzDate.str();

        // Datestamp (YYYMMDD only)
        std::string ssDateStamp = ssAmzDate.substr(0, 8);

        // Service = s3
        std::string ssService = "s3";

        // Request Type = aws4_request
        std::string ssRequestType = "aws4_request";

        // Parse URL
        std::regex urlRegex("(http|https)://([^/ ]+)(/?[^ ]*)");
        std::cmatch what;
        if (!regex_match(url.c_str(), what, urlRegex)) {
            std::string errorMsg{"Failed to parse url, expected:'(http|https)//<domain>/<target>' actual:"};
            errorMsg.append(url);
            ThrowException(std::move(errorMsg));
        }

        // Extract host from parsed URL
        std::string ssHost = std::string(what[2].first, what[2].second);

        // Extract path from parsed URL
        std::string ssPath = std::string(what[3].first, what[3].second);

        // Content is null for a GET
        std::string ssContentSha256;

        ssContentSha256 = crypto::hexHashSha256(toBytes(content));

        // Build request value
        // Example:
        // /us-west-2/s3/aws4_request
        std::string ssRequest = "/";
        ssRequest.append(awsRegionName);
        ssRequest.append("/");
        ssRequest.append(ssService);
        ssRequest.append("/");
        ssRequest.append(ssRequestType);

        // Create canonical request string
        // https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
        // Example:  (note: must be byte-for-byte exact, same capitalization, no extra spaces or newlines)
/*------ EXAMPLE BEGIN
GET
/s3_io_provider_sample.txt

host:patman2.s3.us-west-2.amazonaws.com
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date:20220603T035523Z

host;x-amz-content-sha256;x-amz-date
-------- EXAMPLE END */
        std::string canonicalRequest;

        canonicalRequest.append(httpVerb);
        canonicalRequest.append("\n");
        canonicalRequest.append(ssPath);
        canonicalRequest.append("\n");
        canonicalRequest.append("\n");
        canonicalRequest.append("host:").append(ssHost);
        canonicalRequest.append("\n");
        canonicalRequest.append("x-amz-content-sha256:").append(ssContentSha256);
        canonicalRequest.append("\n");
        canonicalRequest.append("x-amz-date:").append(ssAmzDate);
        canonicalRequest.append("\n");
        canonicalRequest.append("\n");
        canonicalRequest.append("host;x-amz-content-sha256;x-amz-date");
        canonicalRequest.append("\n");
        canonicalRequest.append(ssContentSha256);

        std::string hexcanondata = crypto::hex(toBytes(canonicalRequest));

        // TODO - only do this work if log level is showing debug info
        oss.str("");
        oss << "canonicalRequest=\"" << canonicalRequest << "\"" << std::endl;
        oss << "hex(canonicalRequest)=\"" << hexcanondata << "\"" << std::endl;
        LogDebug(oss.str());

        // Create string to sign
        // https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
        // Example:  (note: must be byte-for-byte exact, same capitalization, no extra spaces or newlines)
/*------ EXAMPLE BEGIN
AWS4-HMAC-SHA256
20150830T123600Z
20150830/us-east-1/s3/aws4_request
f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59
-------- EXAMPLE END */

        const std::string kAwsHmacSha256 = "AWS4-HMAC-SHA256";

        std::string toSign = kAwsHmacSha256;
        toSign.append("\n");
        toSign.append(ssAmzDate);
        toSign.append("\n");
        toSign.append(ssDateStamp);
        toSign.append(ssRequest);
        toSign.append("\n");
        toSign.append(crypto::hexHashSha256(toBytes(canonicalRequest)));

        // Calculate signature on stringToSign
        std::string hextosigndata = crypto::hex(toBytes(toSign));
        std::string computedSignatureAsHex = S3Utilities::generateAwsSignature(ssSecret, ssDateStamp, awsRegionName, ssService, ssRequestType, toSign);

        // TODO - only do this work if log level is showing debug info
        oss.str("");
        oss << "ssSecret=\"" << ssSecret.substr(0,6) << "...\"" << std::endl;
        oss << "ssDateStamp=\"" << ssDateStamp << "\"" << std::endl;
        oss << "ssRegionName=\"" << awsRegionName << "\"" << std::endl;
        oss << "ssService=\"" << ssService << "\"" << std::endl;
        oss << "ssRequest=\"" << ssRequestType << "\"" << std::endl;
        oss << "stringToSign=\"" << toSign << "\"" << std::endl;
        oss << "hex(tosign)=\"" << hextosigndata << "\"" << std::endl;
        oss << "signature=\"" << computedSignatureAsHex << "\"" << std::endl;
        LogDebug(oss.str());

        // Build the credential value
        std::string ssCredential = awsAccessKeyId;
        ssCredential.append("/");
        ssCredential.append(ssDateStamp);
        ssCredential.append(ssRequest);

        // Build the content length value
        // Example:
        // Content-Length: 0
        std::ostringstream osContentLength;
        osContentLength << content.size();
        std::string ssContentLength = osContentLength.str();
        headers.insert_or_assign("Content-Length", ssContentLength);

        // Build the authorization value
        // Example:
        // Authorization: AWS4-HMAC-SHA256 Credential=AKIAWM2OYTV3QKEQ455I/20191213/us-west-2/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=16ae12a3e88c85a63f1476afb2f0886d708f6758316aae28b889a7a40df44941

        std::string ssAuthorization;
        ssAuthorization.append(kAwsHmacSha256);
        ssAuthorization.append(" ");
        ssAuthorization.append("Credential=");
        ssAuthorization.append(ssCredential);
        ssAuthorization.append(", SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=");
        ssAuthorization.append(computedSignatureAsHex);
        headers.insert_or_assign("Authorization", ssAuthorization);

        headers.insert_or_assign("X-Amz-Content-Sha256", ssContentSha256);
        headers.insert_or_assign( "X-Amz-Date", ssAmzDate);
        headers.insert_or_assign(kHostKey, ssHost);
    }
}
