//
// Created by Patrick Mancuso on 3/28/23.
//


#define BOOST_TEST_MODULE test_virtru_ictdf

#include "virtru_ictdf.h"
#include "tdf_exception.h"
#include "boost/test/included/unit_test.hpp"
#include <iostream>
#include <stdio.h>
#include <memory>

using namespace virtru;

BOOST_AUTO_TEST_SUITE(test_virtru_ictdf_suite)

#ifdef _WINDOWS
#include <direct.h>
#define GetCurrentDir _getcwd
#else
#include <unistd.h>
#define GetCurrentDir getcwd
#endif

std::string getCurrentWorkingDir() {
    char buff[FILENAME_MAX];
    GetCurrentDir( buff, FILENAME_MAX );
    std::string current_working_dir(buff);
    return current_working_dir;
}


BOOST_AUTO_TEST_CASE(test_virtru_ictdf_basic) {

    std::string testFilePath {getCurrentWorkingDir()};

#ifdef _WINDOWS
    testFilePath.append("\\data\\some-ictdf.tdf");
#else
    testFilePath.append("/data/some-ictdf.tdf");
#endif


    Ictdf ictdf;
    std::cout << "ictdf created" << std::endl;
    ictdf.parseFile(testFilePath);

    std::cout << "parseFile completed" << std::endl;


}


BOOST_AUTO_TEST_SUITE_END()