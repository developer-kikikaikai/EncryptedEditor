cmake_minimum_required(VERSION 2.8)
INCLUDE_DIRECTORIES("${PROJECT_SOURCE_DIR}/lib/include")
set(CMAKE_VERBOSE_MAKEFILE 1)
add_definitions("-std=c++11")
add_definitions("-g -O2")

ADD_LIBRARY(encrypt_api SHARED encrypt_api.cpp encrypter_factory.cpp)

#target_link_libraries( wifi_landevice jansson )
INSTALL(TARGETS encrypt_api LIBRARY DESTINATION lib)
