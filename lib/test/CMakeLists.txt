cmake_minimum_required(VERSION 2.8)
INCLUDE_DIRECTORIES("${PROJECT_SOURCE_DIR}/lib/include")
link_directories("${PROJECT_SOURCE_DIR}/lib/src")
link_directories("/usr/local/lib")

add_definitions("-g -O2")

add_executable(test_main main.c)
target_link_libraries(test_main encrypt_api cunit)
