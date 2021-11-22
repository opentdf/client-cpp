//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/04.
//  Copyright 2019 Virtru Corporation
//

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <sstream>

#include <nanotdf_client.h>
#include <nanotdf_dataset_client.h>
#include <tdf_client.h>
#include <oidc_credentials.h>

#define STRINGIFY(x) #x
using namespace pybind11::literals;

PYBIND11_MODULE(opentdf, tdf) {

    using namespace virtru;
    namespace py = pybind11;

    tdf.doc() = "Python bindings for the TDF SDK library";

    // Use the version number from VERSION
    //tdf.attr("__version__") = // Get from shared instance;

    py::enum_<LogLevel>(tdf, "LogLevel")
        .value("Trace", LogLevel::Trace)
        .value("Debug", LogLevel::Debug)
        .value("Info", LogLevel::Info)
        .value("Warn", LogLevel::Warn)
        .value("Error", LogLevel::Error)
        .value("Fatal", LogLevel::Fatal);

    py::class_<OIDCCredentials>(tdf, "OIDCCredentials")
        .def(py::init([]() { return new OIDCCredentials();}), R"pbdoc(
              Create an OIDC credentials object
        )pbdoc")
        .def("set_client_credentials", &OIDCCredentials::setClientCredentials,
                py::arg("client_id"), py::arg("client_secret"),
                py::arg("organization_name"), py::arg("oidc_endpoint"), R"pbdoc(
                Set the client credentials that will be use for authz with OIDC server

            Args:
                client_id(string): The client id
                client_secret(string): The client secret
                organization_name(string): The OIDC realm or organization the client belongs to
                oidc_endpoint(string): The OIDC server url
        )pbdoc")
        .def("get_client_id", &OIDCCredentials::getClientId, R"pbdoc(
            Return the client id.
        )pbdoc")
        .def("get_client_secret", &OIDCCredentials::getClientSecret, R"pbdoc(
            Return the client secret.
        )pbdoc")
        .def("get_username", &OIDCCredentials::getUsername, R"pbdoc(
            Return the username.
        )pbdoc")
        .def("get_password", &OIDCCredentials::getPassword, R"pbdoc(
            Return the password for associated user
        )pbdoc")
        .def("get_org_name", &OIDCCredentials::getOrgName, R"pbdoc(
            Return the OIDC realm or organization the client belongs to
        )pbdoc")
        .def("get_oidc_endpoint", &OIDCCredentials::getOIDCEndpoint, R"pbdoc(
            Return the OIDC server url
        )pbdoc")
        .def("__repr__", [](const OIDCCredentials &oidcCredentials) {
            return oidcCredentials.str();
        });

    // TDF Client python wrapper.
    // NOTE: Intentionally have long lines because sed script need to parse for arguments
    py::class_<TDFClient>(tdf, "TDFClient")
        .def(py::init([](const std::string &easUrl, const std::string &user) {
                 return new TDFClient(easUrl, user);
             }),
             py::arg("eas_url"), py::arg("user"), R"pbdoc(
              DEPRECATED - use OIDC constructors instead.
              Create an instance of Client.

              Args:
                 eas_url(string): The eas url.
                 user(string): The registered user on eas.

            )pbdoc")
        .def(py::init([](const std::string &backendUrl, const std::string &user, const std::string &clientKeyFileName, const std::string &clientCertFileName, const std::string &sdkConsumerCertAuthority) {
                 return new TDFClient(
                     backendUrl,
                     user,
                     clientKeyFileName,
                     clientCertFileName,
                     sdkConsumerCertAuthority);
             }),
             py::arg("backend_url"), py::arg("user"), py::arg("client_key_filename"), py::arg("client_cert_filename"), py::arg("sdk_consumer_certauthority"), R"pbdoc(
              Create an instance of Client.

              Args:
                 backend_url(string) - The EAS url
                 user(string): The registered user on eas.
                 client_key_fileName(string): Path to client key file.
                 client_cert_filename(string): Path to client certificate file.
                 sdk_consumer_certauthority(string): Path to cert authority file.
            )pbdoc")
        .def(py::init([](const OIDCCredentials& oidcCredentials, const std::string &kasUrl) {
                     return new TDFClient(oidcCredentials, kasUrl);
                 }),
                 py::arg("oidc_credentials"), py::arg("kas_url"), R"pbdoc(
              Create an instance of Client

              Args:
                 oidc_credentials(OIDCCredentials): OIDC credentials object
                 kas_url(string): The KAS backend url
            )pbdoc")
        .def("share_with_users", &TDFClient::shareWithUsers, py::arg("users_list"), R"pbdoc(
               Add access to the TDF file/data for the users in the list

              Args:
                 users_list(list): Share the TDF with the users in the list
            )pbdoc")
        .def(
            "encrypt_file", [](TDFClient &tdfClient, const std::string &inputFile, const std::string &outFile) { return tdfClient.encryptFile(inputFile, outFile); }, py::arg("in_filename"), py::arg("out_filename"), R"pbdoc(
              Encrypt the file

              Args:
                 in_filename(string) - The file to be encrypted.
                 out_filename(string) - The encrypted file name.

            )pbdoc")
        .def(
            "decrypt_file", [](TDFClient &tdfClient, const std::string &inputFile, const std::string &outFile) { return tdfClient.decryptFile(inputFile, outFile); }, py::arg("in_filename"), py::arg("out_filename"), R"pbdoc(
              Encrypt the file

              Args:
                 in_filename(string) - The file to be decrypted.
                 out_filename(string) - The decrypted file name.

            )pbdoc")
        .def(
            "encrypt_string", [](TDFClient &tdfClient, const std::string &str) { return py::bytes(tdfClient.encryptString(str)); }, py::arg("plain_text"), R"pbdoc(
              Encrypt the string

              Args:
                 plain_text(string) - Plain text to be encrypted.

              Returns:
                 TDF data.
            )pbdoc")
        .def("decrypt_string", &TDFClient::decryptString, py::arg("tdf_data"), R"pbdoc(
              Decrypt the TDF data

              Args:
                 tdf_data(string) - TDF data to be decrypted.

              Returns:
                 Plain data.
            )pbdoc")
        .def(
            "decrypt_bytes", [](TDFClient &tdfClient, const std::string &tdfData) { return py::bytes(tdfClient.decryptString(tdfData)); }, py::arg("tdf_data"), R"pbdoc(
              Decrypt the TDF data

              Args:
                 tdf_data(string) - TDF data to be decrypted.

              Returns:
                 Plain data.
            )pbdoc")
        .def("enable_console_logging", &TDFClient::enableConsoleLogging, py::arg("log_level"), R"pbdoc(
              Enable the logger to write logs to the console

              Note: The default is LogLevel::Warn

              Args:
                 log_level(LogLevel): The log level

            )pbdoc")
        .def("subject_attributes", &TDFClient::getSubjectAttributes, R"pbdoc(
              Get subject attributes

              Returns:
                 Subject attribute URIs.
            )pbdoc")
        .def("add_data_attribute", &TDFClient::addDataAttribute, py::arg("data_attribute"), py::arg("display_name"), py::arg("kas_public_key"), py::arg("kas_url"), R"pbdoc(
               Add data attribute

              Args:
                 data_attribute(string): Add a data attribute to the TDF policy. Should be a URI.
                 display_name(string): 'Friendly name' for attribute. Can be an empty string.
                 kas_public_key(string): Public key of the KAS instance this attribute is associated with.
                 kas_url(string): URL of the KAS instance this attribute is associated with.
            )pbdoc");

    // Nano TDF Client python wrapper.
    // NOTE: Intentionally have long lines because sed script need to parse for arguments
    py::class_<NanoTDFClient>(tdf, "NanoTDFClient")
        .def(py::init([]() { return new NanoTDFClient(); }), R"pbdoc(
              Create an instance of nano tdf client.
              NOTE: should me used for only offline decrypt operation.
            )pbdoc")
        .def(py::init([](const std::string &easUrl, const std::string &user) {
                 return new NanoTDFClient(easUrl, user);
             }),
             py::arg("eas_url"), py::arg("user"), R"pbdoc(
              Create an instance of nano tdf client.

              Args:
                 eas_url(string): The eas url.
                 user(string): The registered user on eas.

            )pbdoc")
        .def(py::init([](const std::string &easUrl, const std::string &user, const std::string &clientKeyFileName, const std::string &clientCertFileName, const std::string &sdkConsumerCertAuthority) {
                 return new NanoTDFClient(easUrl, user, clientKeyFileName, clientCertFileName, sdkConsumerCertAuthority);
             }),
             py::arg("eas_url"), py::arg("user"), py::arg("clientKeyFileName"), py::arg("clientCertFileName"), py::arg("sdkConsumerCertAuthority"), R"pbdoc(
              Create an instance of nano tdf client.

              Args:
                 eas_url(string): The eas url.
                 user(string): The registered user on eas.
                 clientKeyFileName(string): Path to client key file.
                 clientCertFileName(string): Path to client certificate file.
                 sdkConsumerCertAuthority(string): Path to cert authority file.
            )pbdoc")
        .def(py::init([](const OIDCCredentials& oidcCredentials, const std::string &kasUrl) {
                     return new NanoTDFClient(oidcCredentials, kasUrl);
                 }),
                 py::arg("oidc_credentials"), py::arg("kas_url"), R"pbdoc(
              Create an instance of Client

              Args:
                 oidc_credentials(OIDCCredentials): OIDC credentials object
                 kas_url(string): The KAS backend url
        )pbdoc")
        .def_static("is_valid_nano_tdf_file", &NanoTDFClient::isValidNanoTDFFile,  py::arg("in_filename") ,R"pbdoc(
               Check if the file is in valid NanoTDF format.

              Args:
                 in_filename(string) - The NanoTDF file
            )pbdoc")
        .def_static("is_valid_nano_tdf_data", &NanoTDFClient::isValidNanoTDFData,  py::arg("tdf_data") ,R"pbdoc(
               Check if the data is in valid NanoTDF format.

              Args:
                 tdf_data(string) - The NanoTDF data
            )pbdoc")
        .def("share_with_users", &NanoTDFClient::shareWithUsers, py::arg("users_list"), R"pbdoc(
               Add access to the TDF file/data for the users in the list

              Args:
                 users_list(list): Share the TDF with the users in the list
            )pbdoc")
        .def(
            "encrypt_file", [](NanoTDFClient &nanoTdfClient, const std::string &inputFile, const std::string &outFile) { return nanoTdfClient.encryptFile(inputFile, outFile); }, py::arg("in_filename"), py::arg("out_filename"), R"pbdoc(
              Encrypt the file

              Args:
                 in_filename(string) - The file to be encrypted.
                 out_filename(string) - The encrypted file name.

            )pbdoc")
        .def(
            "decrypt_file", [](NanoTDFClient &nanoTdfClient, const std::string &inputFile, const std::string &outFile) { return nanoTdfClient.decryptFile(inputFile, outFile); }, py::arg("in_filename"), py::arg("out_filename"), R"pbdoc(
              Encrypt the file

              Args:
                 in_filename(string) - The file to be decrypted.
                 out_filename(string) - The decrypted file name.

            )pbdoc")
        .def(
             "decrypt_file_using_old_format", [](NanoTDFClient &nanoTdfClient, const std::string &inputFile, const std::string &outFile) { return nanoTdfClient.decryptFileUsingOldFormat(inputFile, outFile); }, py::arg("in_filename"), py::arg("out_filename"), R"pbdoc(
              Encrypt the file that are encrypted using old version of SDKs

              Args:
                 in_filename(string) - The file to be decrypted.
                 out_filename(string) - The decrypted file name.

            )pbdoc")
        .def(
            "encrypt_string", [](NanoTDFClient &nanoTdfClient, const std::string &str) { return py::bytes(nanoTdfClient.encryptString(str)); }, py::arg("plain_text"), R"pbdoc(
              Encrypt the string

              Args:
                 plain_text(string) - Plain text to be encrypted.

              Returns:
                 TDF data.
            )pbdoc")
        .def(
            "decrypt_string", [](NanoTDFClient &nanoTdfClient, const std::string &tdfData) { return py::bytes(nanoTdfClient.decryptString(tdfData)); }, py::arg("tdf_data"), R"pbdoc(
              Decrypt the TDF data

              Args:
                 tdf_data(string) - TDF data to be decrypted.

              Returns:
                 Plain data.
            )pbdoc")
        .def(
             "decrypt_string_using_old_format", [](NanoTDFClient &nanoTdfClient, const std::string &tdfData) { return py::bytes(nanoTdfClient.decryptStringUsingOldFormat(tdfData)); }, py::arg("tdf_data"), R"pbdoc(
              Decrypt the TDF data that are encrypted using old version of SDKs

              Args:
                 tdf_data(string) - TDF data to be decrypted.

              Returns:
                 Plain data.
            )pbdoc")
        .def("validate_signature", &NanoTDFClient::validateSignature, py::arg("signer_public_key"), R"pbdoc(
              Validate the TDF on decrypt(check if the TDF is singed by right entity).
              Throws exception on decrypt if the given public key doesn't match the one in TDF.

              Args:
                 signer_public_key(string): The PEM-encoded public key as a string.
            )pbdoc")
        .def(
            "set_entity_private_key", [](NanoTDFClient &nanoTdfClient, const std::string &entityPrivateKey) { nanoTdfClient.setEntityPrivateKey(entityPrivateKey, EllipticCurve::SECP256R1); }, py::arg("entity_private_key"), R"pbdoc(
              Set the entity private key(In PEM format), which will be used by this SDK for encryption/decryption of
              the payload/policy

              NOTE: The private key should be from curve secp256r1

              Args:
                 entity_private_key(string): The PEM-encoded private key as a string.
            )pbdoc")
        .def(
            "set_signer_private_key", [](NanoTDFClient &nanoTdfClient, const std::string &signerPrivateKey) { nanoTdfClient.setSignerPrivateKey(signerPrivateKey, EllipticCurve::SECP256R1); }, py::arg("signer_private_key"), R"pbdoc(
              Set the signer private key(In PEM format). Calling this method enables the signature entry in nano tdf

              NOTE: The private key should be from curve secp256r1

              Args:
                 signer_private_key(string): The PEM-encoded private key as a string.
            )pbdoc")
        .def("set_decrypter_public_key", &NanoTDFClient::setDecrypterPublicKey, py::arg("decrypter_public_key"), R"pbdoc(
              Set the kas decrypter public-key(In PEM format). This can be used for offline mode.

              NOTE: The public key should be from curve secp256r1

              Args:
                 decrypter_public_key(string): The PEM-encoded public key as a string.
            )pbdoc")
        .def(
            "get_entity_private_key", [](NanoTDFClient &nanoTdfClient) {
                auto keyAndCurve = nanoTdfClient.getEntityPrivateKeyAndCurve(); return keyAndCurve.first; }, R"pbdoc(
              Return the entity private key in PEM format.

              Returns:
                 The entity private key in PEM format.
            )pbdoc")
        .def("enable_console_logging", &NanoTDFClient::enableConsoleLogging, py::arg("log_level"), R"pbdoc(
              Enable the logger to write logs to the console

              Note: The default is LogLevel::Warn

              Args:
                 log_level(LogLevel): The log level
            )pbdoc")
        .def("subject_attributes", &NanoTDFClient::getSubjectAttributes, R"pbdoc(
              Get subject attributes

              Returns:
                 Subject attribute URIs.
            )pbdoc")
        .def("add_data_attribute", &NanoTDFClient::addDataAttribute, py::arg("data_attribute"), py::arg("display_name"), py::arg("kas_public_key"), py::arg("kas_url"), R"pbdoc(
               Add data attribute

              Args:
                 data_attribute(string): Add a data attribute to the TDF policy. Should be a URI.
                 display_name(string): 'Friendly name' for attribute. Can be an empty string.
                 kas_public_key(string): Public key of the KAS instance this attribute is associated with.
                 kas_url(string): URL of the KAS instance this attribute is associated with.
            )pbdoc");

    // Nano TDF Client python wrapper.
    // NOTE: Intentionally have long lines because sed script need to parse for arguments
    py::class_<NanoTDFDatasetClient>(tdf, "NanoTDFDatasetClient")
        .def(py::init([](uint32_t maxKeyIterations) { return new NanoTDFDatasetClient(maxKeyIterations); }),
             py::arg("max_key_iterations") = kNTDFMaxKeyIterations, R"pbdoc(
              Create an instance of nano tdf dataset client.

              Args:
                 max_key_iterations(int) - Maximum number of encrypt operations before a new key is generated.(default is 8388607).

              NOTE: should me used for only offline decrypt operation.
            )pbdoc")
        .def(py::init([](const std::string &easUrl, const std::string &user, uint32_t maxKeyIterations) {
                 return new NanoTDFDatasetClient(easUrl, user, maxKeyIterations);
             }),
             py::arg("eas_url"), py::arg("user"), py::arg("max_key_iterations") = kNTDFMaxKeyIterations, R"pbdoc(
              Create an instance of nano tdf dataset client.

              Args:
                 eas_url(string): The eas url.
                 user(string): The registered user on eas.
                 max_key_iterations(int) - Maximum number of encrypt operations before a new key is generated.(default is 8388607).

            )pbdoc")
        .def(py::init([](const std::string &easUrl, const std::string &user, const std::string &clientKeyFileName,
                         const std::string &clientCertFileName, const std::string &sdkConsumerCertAuthority, uint32_t maxKeyIterations) {
                 return new NanoTDFDatasetClient(easUrl, user, clientKeyFileName, clientCertFileName, sdkConsumerCertAuthority, maxKeyIterations);
             }),
             py::arg("eas_url"), py::arg("user"), py::arg("clientKeyFileName"), py::arg("clientCertFileName"),
             py::arg("sdkConsumerCertAuthority"), py::arg("max_key_iterations") = kNTDFMaxKeyIterations, R"pbdoc(
              Create an instance of nano tdf client.

              Args:
                 eas_url(string): The eas url.
                 user(string): The registered user on eas.
                 clientKeyFileName(string): Path to client key file.
                 clientCertFileName(string): Path to client certificate file.
                 sdkConsumerCertAuthority(string): Path to cert authority file.
                 max_key_iterations(int) - Maximum number of encrypt operations before a new key is generated.(default is 8388607).
            )pbdoc")
        .def("share_with_users", &NanoTDFDatasetClient::shareWithUsers, py::arg("users_list"), R"pbdoc(
               Add access to the TDF file/data for the users in the list

              Args:
                 users_list(list): Share the TDF with the users in the list
            )pbdoc")
        .def(
            "encrypt_file", [](NanoTDFDatasetClient &nanoTdfDatasetClient, const std::string &inputFile, const std::string &outFile) { return nanoTdfDatasetClient.encryptFile(inputFile, outFile); }, py::arg("in_filename"), py::arg("out_filename"), R"pbdoc(
              Encrypt the file

              Args:
                 in_filename(string) - The file to be encrypted.
                 out_filename(string) - The encrypted file name.

            )pbdoc")
        .def(
            "decrypt_file", [](NanoTDFDatasetClient &nanoTdfDatasetClient, const std::string &inputFile, const std::string &outFile) { return nanoTdfDatasetClient.decryptFile(inputFile, outFile); }, py::arg("in_filename"), py::arg("out_filename"), R"pbdoc(
              Encrypt the file

              Args:
                 in_filename(string) - The file to be decrypted.
                 out_filename(string) - The decrypted file name.

            )pbdoc")
        .def(
            "encrypt_string", [](NanoTDFDatasetClient &nanoTdfDatasetClient, const std::string &str) {
                const auto& data = nanoTdfDatasetClient.encryptString(str);
                return py::bytes(data.data(), data.size()); }, py::arg("plain_text"), R"pbdoc(
              Encrypt the string

              Args:
                 plain_text(string) - Plain text to be encrypted.

              Returns:
                 TDF data.
            )pbdoc")
        .def(
            "decrypt_string", [](NanoTDFDatasetClient &nanoTdfDatasetClient, const std::string &tdfData) {
                const auto& data = nanoTdfDatasetClient.decryptString(tdfData);
                return py::bytes(data.data(), data.size()); }, py::arg("tdf_data"), R"pbdoc(
              Decrypt the TDF data

              Args:
                 tdf_data(string) - TDF data to be decrypted.

              Returns:
                 Plain data.
            )pbdoc")
        .def("validate_signature", &NanoTDFDatasetClient::validateSignature, py::arg("signer_public_key"), R"pbdoc(
              Validate the TDF on decrypt(check if the TDF is singed by right entity).
              Throws exception on decrypt if the given public key doesn't match the one in TDF.

              Args:
                 signer_public_key(string): The PEM-encoded public key as a string.
            )pbdoc")
        .def(
            "set_entity_private_key", [](NanoTDFDatasetClient &nanoTdfDatasetClient, const std::string &entityPrivateKey) { nanoTdfDatasetClient.setEntityPrivateKey(entityPrivateKey, EllipticCurve::SECP256R1); }, py::arg("entity_private_key"), R"pbdoc(
              Set the entity private key(In PEM format), which will be used by this SDK for encryption/decryption of
              the payload/policy

              NOTE: The private key should be from curve secp256r1

              Args:
                 entity_private_key(string): The PEM-encoded private key as a string.
            )pbdoc")
        .def(
            "set_signer_private_key", [](NanoTDFDatasetClient &nanoTdfDatasetClient, const std::string &signerPrivateKey) { nanoTdfDatasetClient.setSignerPrivateKey(signerPrivateKey, EllipticCurve::SECP256R1); }, py::arg("signer_private_key"), R"pbdoc(
              Set the signer private key(In PEM format). Calling this method enables the signature entry in nano tdf

              NOTE: The private key should be from curve secp256r1

              Args:
                 signer_private_key(string): The PEM-encoded private key as a string.
            )pbdoc")
        .def("set_decrypter_public_key", &NanoTDFDatasetClient::setDecrypterPublicKey, py::arg("decrypter_public_key"), R"pbdoc(
              Set the kas decrypter public-key(In PEM format). This can be used for offline mode.

              NOTE: The public key should be from curve secp256r1

              Args:
                 decrypter_public_key(string): The PEM-encoded public key as a string.
            )pbdoc")
        .def(
            "get_entity_private_key", [](NanoTDFDatasetClient &nanoTdfDatasetClient) {
                auto keyAndCurve = nanoTdfDatasetClient.getEntityPrivateKeyAndCurve(); return keyAndCurve.first; }, R"pbdoc(
              Return the entity private key in PEM format.

              Returns:
                 The entity private key in PEM format.
            )pbdoc")
        .def("enable_console_logging", &NanoTDFDatasetClient::enableConsoleLogging, py::arg("log_level"), R"pbdoc(
              Enable the logger to write logs to the console

              Note: The default is LogLevel::Warn

              Args:
                 log_level(LogLevel): The log level
            )pbdoc")
        .def("add_data_attribute", &NanoTDFDatasetClient::addDataAttribute, py::arg("data_attribute"), py::arg("display_name"), py::arg("kas_public_key"), py::arg("kas_url"), R"pbdoc(
               Add data attribute

              Args:
                 data_attribute(string): Add a data attribute to the TDF policy. Should be a URI.
                 display_name(string): 'Friendly name' for attribute. Can be an empty string.
                 kas_public_key(string): Public key of the KAS instance this attribute is associated with.
                 kas_url(string): URL of the KAS instance this attribute is associated with.
            )pbdoc");
}
