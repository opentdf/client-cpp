# C++ OSS Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

### Added
0.6.2
- PLAT-1626 Fix the regression caused XML TDF generation and json library update

0.6.1
- PLAT-1640 Update to BSD license

0.6.0
- Updates for networking changes

0.5.3
- PLAT-1592/PLAT-1593 Fix build - manylinux and rpi armv8

0.5.2
- SA-354 Fix issue with network provider handling

0.5.1
- Bump `libarchive` to 3.5.2

0.5.0
- SA-354 Add `getPolicy` support

0.4.0
- PLAT-1371 Add OIDC Token Exchange support

0.3.0
- PLAT-1371 Add C interoperability layer

0.2.12
- PLAT-1365 Switch GSL library

0.2.11
- PLAT-1520 Add PKI/mTLS support

0.2.10
- Updated copyright headers

0.2.9
- PLAT-1454 Fix windows conan build

0.2.8
- PLAT-1454 Expose more header files to published include area

0.2.7
- PLAT-1490 Fix API for adding the data attributes for C++ SDK 

0.2.6
- PLAT-1431 SDK XML interoperability 
  
0.2.5
- PLAT-1296 Renames from code review

0.2.4
- PLAT-1467 Split python to separate repo
- PLAT-1466 Split conan to separate repo
- PLAT-1458 fixed bug in json conversion

0.2.3
- PLAT-1458 Added trace calls, fixed bug in json conversion

0.2.2
- Reworked dataAttribute method

0.2.1
- Fixed missing package references in conan recipe

0.2.0
- PLAT-1452 drop legacy `withDataAttributes` API and stick with (simpler) `addDataAttribute`

0.1.3
- PLAT-1160 support python 3.9

0.1.2
- PLAT-1291 upgrade json library
- PLAT-1290 upgrade jwt library

0.1.1
- PLAT-1381 Change all TDF3 mentions to TDF

0.1.0
- Change version numbering in preparation for opentdf

1.2.9
- PLAT-1324 Change the library name from tdf to opentdf

1.2.8
- PLAT-1345 C++ SDK support PE authorization for OIDC
- 
1.2.7
- PLAT-1323 Remove the owner field from OIDCCredentials class
  
1.2.6
- PLAT-1273 API to add attributes to the policy and API to get the subject attributes from OIDC

1.2.5
- PLAT-1188 NanoTDF IV changed from 3 bytes to 12 bytes(Fix the container size)

1.2.4
- PLAT-1242 OIDC flow should validate request body for NanoTDF/TDF rewrap request

1.2.3
- PLAT-1234 Openstack OIDC support for NanoTDF

1.2.2
- PLAT-1223 Openstack OIDC support for TDF

1.2.1
- PLAT-1178 Updated conan remotes and version tags

1.2.0
- PLAT-1209 C# Bindings
- PLAT-1188 NanoTDF IV changed from 3 bytes to 12 bytes
- PLAT-1158 New API for encrypt/decrypt to deal with bytes
- PLAT-1146 Add Java bindings
- PLAT-1149 Interface to validate the NanoTDF schema
- SA-275 Add initial OIDC auth and KAS v2 API support
- PLAT-1031 Remove references to obsolete kas_public_key endpoint
- PLAT-1015 Don't use ECDSA by default
- PLAT-791 Dataset nano TDF first version of changes
- PLAT-617 adds `withDataAttributes` function to client to allow user to add data attributes
- PLAT-624 adds `getEntityAttributes` function to client to allow user to read entity attributes
- PLAT-445 Nano TDF first version of changes
- PLAT-700 Support for Nano TDF

1.0.5: 
- SA-177 Support for VJWT
- SA-177 Added setUser method to support VJWT
- SA-228 Avoid resetting LogLevel, add LogLevel::Current

### Fixed
