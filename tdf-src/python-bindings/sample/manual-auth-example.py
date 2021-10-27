# Copyright Virtru Corporation
#
# SPDX - License - Identifier: MIT
#

# Normally you'd use the `virtru-sdk` wrapper to handle auth routines
# and obtain a Virtru bearer token, but this shows a few different examples of
# how to manually obtain a bearer token if using this library standalone
import sys
import requests
import faulthandler; faulthandler.enable()
import base64

from opentdf import TDFClientBase, LogLevel

# TODO set this to point at the public key
# for the keypair you intend to use for TDF encrypt/decrypt
# Whatever public key you use to obtain a bearer token with is the
# key you should use for client crypto.
clientPubKeyPath = "/path/to/client/pubkey"
# TODO set this to point to Virtru's auth provider, or if using custom flows,
# a valid OIDC identity provider with custom claims support.
virtruAuthEndpoint = "https://virtru.com/todo-auth"
# TODO set this to your Virtru-issued clientId
virtruClientId = "vClient2"
# TODO set this to your Virtru-issued clientsecret
virtruClientSecret = "vClientSecret"

def readClientPubkey(filename):
    with open(filename) as f:
        content = f.readlines()

    return content

def exchange3rdPartyIdPTokenForTDFToken():

    clientPubKey = base64.b64encode(readClientPubkey(clientPubKeyPath))
    # In this example, a base64 encoded JWT, previously obtained from another IdP
    # TODO set this to a valid value
    thirdPartyToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiA..."

    exchangeBody = {
        'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
        'client_id': virtruClientId,
        'client_secret': virtruClientSecret,
        'requested_token_type': 'urn:ietf:params:oauth:token-type:access_token',
        'subject_token': thirdPartyToken,
        'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token'
    }

    result = requests.post(virtruAuthEndpoint, exchangeBody, headers={'X-Virtru-Pubkey': clientPubKey})

    return result.access_token

def exchangeClientCredentialsForTDFToken():

    clientPubKey = base64.b64encode(readClientPubkey(clientPubKeyPath))

    exchangeBody = {
        'grant_type': 'client_credentials',
        'client_id': virtruClientId,
        'client_secret': virtruClientSecret,
    }

    result = requests.post(virtruAuthEndpoint, exchangeBody, headers={'X-Virtru-Pubkey': clientPubKey})

    return result.access_token

def doVirtruEncryptDecrypt(authToken):

    # encrypt the file and apply the policy on tdf file and also decrypt.
    try:
        # # Create a client via OIDC
        # # TODO: Put your owner email, default KAS url here
        # user/owner is purely informational and not used for auth.
        client = TDFClientBase(
            backend_url = 'http://0.0.0.0:8010',
            user = 'Alice_1234',
            client_cert_filename = clientPubKeyPath,
            use_oidc=True)

        # # Create client with bearer token obtained by exchanging 3rd party token for
        # # Virtru token via OIDC
        tdfBearerToken = exchange3rdPartyIdPTokenForTDFToken()

        # Inject bearer token with TDF claims as the bearer token used
        # for requests to the backend.
        client.set_auth_header(authToken)

        client.enable_console_logging(LogLevel.Trace)
        #################################################
        # TDF - File API
        ################################################

        client.encrypt_file("sample.txt", "sample.txt.tdf")
        client.decrypt_file("sample.txt.tdf", "sample_out.txt")

        #################################################
        # TDF - Data API
        #################################################

        plain_text = 'Hello world!!'
        tdf_data = client.encrypt_string(plain_text)
        decrypted_plain_text = client.decrypt_string(tdf_data)

        if plain_text == decrypted_plain_text:
            print("TDF Encrypt/Decrypt is successful!!")
        else:
            print("Error: TDF Encrypt/Decrypt failed!!")

    except:
        print("Unexpected error: %s" % sys.exc_info()[0])
        raise


def main():
    token1 = exchangeClientCredentialsForTDFToken()
    doVirtruEncryptDecrypt(token1)

    token2 = exchange3rdPartyIdPTokenForTDFToken()
    doVirtruEncryptDecrypt(token2)
