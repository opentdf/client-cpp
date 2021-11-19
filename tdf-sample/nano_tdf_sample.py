# sample encrypt/decrypt
import sys
from opentdf import NanoTDFClient, LogLevel

# Nemo use case
# Command and control send the command to the device as nano tdf payload.
#
# C&C have a knowledge of all devices public-key.
# All devices are pinned with it a unique key-pair and also with C&C public-key.
#
#
c_and_c_private_key = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgi/Qr/jF1vkvCtVRn
JH25ie37emp8icaowPqgIkFvQgihRANCAARlujKGIcl2ibpir9JKycCnjLZG5Ald
6G4o6B340ejGV2XWyyARligEcCCXXeHDe/cfBQm/ODavaNUuZoxp130L
-----END PRIVATE KEY-----
"""

c_and_c_public_key = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZboyhiHJdom6Yq/SSsnAp4y2RuQJ
XehuKOgd+NHoxldl1ssgEZYoBHAgl13hw3v3HwUJvzg2r2jVLmaMadd9Cw==
-----END PUBLIC KEY-----
"""

device_private_key = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6mmuN1BioAfiu6M4
h5hmxAhS6+F/8X8B88cP0Cfb9lKhRANCAATZJTU/gQIUrhXf9jHHb2qDCpuIL3Mr
im3bU/cOdkEm5+Hrb9s1iFCQvdVD2gzXcW9wqlsh/oeLzevLQ7a+YTmZ
-----END PRIVATE KEY-----
"""

device_public_key = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2SU1P4ECFK4V3/Yxx29qgwqbiC9z
K4pt21P3DnZBJufh62/bNYhQkL3VQ9oM13FvcKpbIf6Hi83ry0O2vmE5mQ==
-----END PUBLIC KEY-----
"""

def c_and_c_encrypt_command(command):
    # Command and Control encrypting the command.
    nano_tdf_client = NanoTDFClient(eas_url = 'http://0.0.0.0:4010', user = 'Alice_1234')
    nano_tdf_client.enable_console_logging(LogLevel.Info)

    # Send the decrypter public key so only the device can decrypt in offline mode.
    nano_tdf_client.set_decrypter_public_key(device_public_key)

    nano_tdf_client.set_signer_private_key(c_and_c_private_key)
    tdf = nano_tdf_client.encrypt_string(command)

    return tdf

def device_decrypt(command_as_tdf):

    nano_tdf_client = NanoTDFClient()
    nano_tdf_client.enable_console_logging(LogLevel.Info)

    # SDK has access to device key-pair
    nano_tdf_client.set_entity_private_key(device_private_key)

    # make sure the command is trusted C&C
    # every device is deployed with C&C public key
    nano_tdf_client.validate_signature(c_and_c_public_key)

    # decrypt the tdf.
    command = nano_tdf_client.decrypt_string(command_as_tdf)
    return command

def run_camera_use_case():
    data_store = []

    ######## Device have network at setup time and later goes offline later ###########    
    init_phase_client = NanoTDFClient(eas_url = 'http://0.0.0.0:4010', user = 'Alice_1234')
    init_phase_client.enable_console_logging(LogLevel.Info)

    # TODO: Once KAS work is completed.
    #nano_tdf_client.add_data_attrinutes()

    # Install success
    inital_tdf = init_phase_client.encrypt_string("Installed success!!")
    data_store.append(inital_tdf)

    # save the so the encrypt can be performed later even when there is no network.
    eo_as_string = init_phase_client.get_entity_object_as_json_string()
    entity_private_key = init_phase_client.get_entity_private_key()

    # no network connectivity.
    second_phase_client = NanoTDFClient(eas_url = 'http://0.0.0.0:4010', user = 'Alice_1234')
    second_phase_client.enable_console_logging(LogLevel.Info)

    second_phase_client.set_entity_private_key(entity_private_key)
    second_phase_client.set_entity_object_as_json_string(eo_as_string)

    tdf = second_phase_client.encrypt_string("some data")
    data_store.append(tdf)

    return data_store

if __name__ == "__main__": 

    ######## Command And Control - Use case ###########

    # Operation on C&C
    command_as_tdf = c_and_c_encrypt_command("Collect Data")

    # Operation on Raspberry-Pi(offline) - no network
    command = device_decrypt(command_as_tdf)

    if command.decode('utf-8') == "Collect Data":
        print("C&C use case is successful")
    else:
        print("Error:C&C use case failed!!")

    # Install the camera and run the setup and collect some data.
    data_store = run_camera_use_case()

    # decrypt the data from data store.
    nano_tdf_client_on_x86 = NanoTDFClient(eas_url = 'http://0.0.0.0:4010', user = 'Alice_1234')
    #nano_tdf_client_on_x86.enable_console_logging(LogLevel.Info)

    for tdf in data_store:
        plain_data = nano_tdf_client_on_x86.decrypt_string(tdf)
        print(plain_data.decode('utf-8'))
