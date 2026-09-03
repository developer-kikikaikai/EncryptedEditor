cmake_minimum_required(VERSION 3.10)
#refer https://gist.github.com/adobkin/1073354
#find file to 
find_path(CUNIT_INCLUDE_DIR NAMES CUnit/CUnit.h)
find_library(CUNIT_LIBRARY NAMES cunit)
#To display GUI
#MARK_AS_ADVANCED(CUNIT_LIBRARY)
#find with Cunit option
find_package_handle_standard_args(CUnit DEFAULT_MSG CUNIT_LIBRARY CUNIT_INCLUDE_DIR)

#only build test if env has CUNIT
IF(CUNIT_FOUND)
add_executable(test_main main.c)
target_include_directories(test_main PRIVATE ${CUNIT_INCLUDE_DIR})
target_link_libraries(test_main encrypt_api ${CUNIT_LIBRARY})
add_test(NAME encrypt_api_cunit COMMAND test_main)
ENDIF(CUNIT_FOUND)
