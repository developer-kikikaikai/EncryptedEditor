cmake_minimum_required(VERSION 2.8)
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README")
project(encrypt_editor C CXX)
enable_language(CXX)

add_definitions("-Wall -g -O2")
add_subdirectory(apps)
add_subdirectory(lib)
