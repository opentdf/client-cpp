# Conan recipe
Recipe for publishing to conan repositories

## Process for releasing a new version

1. Update the opentdf/client repository with changes as usual, and merge to `main`
2. Update the CHANGELOG and VERSION files, if necessary, to reflect the new version number and merge to `main`
3. Go to the [releases page](https://github.com/opentdf/client/releases)
4. Create a new tag and release using the new version number
5. Copy the URL for the zipfile of the release under 'Assets'
6. Download the zipfile and get the sha256 (mac/linux: `shasum -a 256 <zip file name>` )
7. Create a release branch from `main`
8. Update the file `conandata.yml` and add a new entry for the release with the URL and sha256
9. Publish to conan per instructions (see below)
10. Merge the release branch into `main`

## Publishing to a conan repository

### conan-center:

Create a PR to update the materials in the `opentdf-client` recipe in the index.  The PR will be merged into the conan-center master index when it is approved.

Documentation for publishing to conan-center is [here](https://github.com/conan-io/conan-center-index/blob/master/docs/how_to_add_packages.md)

To test the recipe locally
`cd <directory containing this README.md>`
`conan create recipe/all opentdf-client/<Version number such as 1.0.0>@ -pr:b=default --build=opentdf-client`

To ensure a clean test, run `conan remove opentdf-client` to delete it from conan's cache and delete the `recipe/all/test_package/build` directory to remove stale test package build artifacts.

Do not check in the `all/test_package/build` directory, ignore or delete it before submitting changes

### Nexus:

`conan upload virtru-nexus opentdf-client`

