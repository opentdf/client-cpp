## NanoTDF

NanoTDF is a library that offers a compact, lightweight, but cryptographically resilient alternative to the traditional TDF. For more information on the NanoTDF specification, see the [NanoTDF spec](https://github.com/opentdf/spec/tree/main/schema/nanotdf). 

### Usage
Invoke NanoTDF by instatiating a NanoTDF Client using these constrcutors (more in source):

https://github.com/opentdf/client-cpp/blob/main/src/lib/src/nanotdf_dataset_client.cpp#L26-L41

The clients can then be used to encrypt and decrypt files:

https://github.com/opentdf/client-cpp/blob/b92902ca85be3d9599525fe7df261ae79b4782eb/src/tests/test_tdf_using_local_kas_eas.cpp#L148-L183

Functional differences in NanoTDF expose the ability to reuse the same key across operations via the dataset client. Creating a dataset client is simple:

https://github.com/opentdf/client-cpp/blob/b92902ca85be3d9599525fe7df261ae79b4782eb/src/tests/test_nano_tdf_dataset.cpp#L52-L108

#### Key caching

You can configure the number of "chunks", or elements in the dataset. For all elements in the dataset, the same key is used. The way to configure this is to set the in the constrcutor.

https://github.com/opentdf/client-cpp/blob/main/src/lib/include/nanotdf_dataset_client.h#L25-L40
...

### Examples

This elliptic curve [test](https://github.com/opentdf/client-cpp/blob/main/src/tests/test_ec_key_pair.cpp) details the programmatic implenentation of NanoTDF. 