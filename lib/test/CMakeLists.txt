cmake_minimum_required(VERSION 2.8)
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
include_directories("${PROJECT_SOURCE_DIR}/lib/include")
include_directories(${CUNIT_INCLUDEDIR})
link_directories("${PROJECT_SOURCE_DIR}/lib/src")
link_directories(${CUNIT_LIBDIR})

add_definitions("-g -O2")

add_executable(test_main main.c)
target_link_libraries(test_main encrypt_api ${CUNIT_LIBRARY})
ENDIF(CUNIT_FOUND)
