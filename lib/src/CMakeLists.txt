cmake_minimum_required(VERSION 2.8)
INCLUDE_DIRECTORIES("${PROJECT_SOURCE_DIR}/lib/include")

add_definitions("-g -O2")

ADD_LIBRARY(encrypt_api SHARED encrypt_api.c  encrypter_factory.c)

#target_link_libraries( wifi_landevice jansson )
INSTALL(TARGETS encrypt_api LIBRARY DESTINATION lib)
