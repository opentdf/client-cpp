# OpenTDF SDK

The OpenTDF Python SDK allows developers to easily create and manage encrypted [Trusted Data Format (TDF) objects](https://github.com/virtru/tdf-spec/) and interact with [Key Access and Attribute Provider services (KAS, AP).](https://github.com/virtru/tdf-spec/tree/master/protocol)

## Installation

Upgrade pip3 to the latest version and run

```shell
pip3 install opentdf
```

## Backend services

To perform any TDF operation, first start the backend services. [Follow the opentdf backend instructions here](https://github.com//opentdf/documentation/tree/main//quickstart) to get going quickly.

## Authentication 

The OpenTDF team has chosen [Keycloak](https://www.keycloak.org) as its reference implementation IdP.

The OpenTDF SDK uses OIDC as authentication and authorization to verify the client has access on behalf of an entity or the a certain level of access appropriate to its subject attributes. The opentdf SDK currently supports only client attributes, not user or person entity attributes. First, [create a client application in keycloak](https://www.keycloak.org/docs/latest/authorization_services/#_resource_server_create_client)

Use the client creds to create an `OIDCCredentials` instance and pass into the `TDFClientBase` or `NanoTDFClient`. With the client initialized as such, you can use it  to perform encrypt/decrypt operations on behalf of the assigned client profile.

## Access control

OpenTDF enables the access control of the data by enabling attributes. The key access ABAC backend service can be used to add and remove attribute values to the client application.

Applying a data attribute to the TDF can be done using this SDK api.

```python
client.add_data_attribute("https://example.com/attr/Classification/value/S", "Classification", "optionalKasKey", "optionalKasUrl")
```


## Create TDF Object (minimal example)

```python
from opentdf import TDFClientBase

oidc_creds = OIDCCredentials()
oidc_creds.set_client_credentials(client_id = "tdf-client",
                                 client_secret = "123-456",
                                 organization_name = "tdf",
                                 oidc_endpoint = "https://localhost:8443")

client = TDFClientBase(oidc_credentials = oidc_creds, kas_url = 'http://localhost:8080/kas')

client.encrypt_file("sensitive.txt", "sensitive.txt.tdf")
client.decrypt_file("sensitive.txt.tdf", "sensitive_plain.txt")

```

[Terms of Service](https://www.virtru.com/terms-of-service/)
[Privacy Policy](https://www.virtru.com/privacy-policy/)
