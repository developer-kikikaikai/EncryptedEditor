cmake_minimum_required(VERSION 2.8)
include_directories("${PROJECT_SOURCE_DIR}/lib/include")
include_directories("${PROJECT_SOURCE_DIR}/lib/src")
include_directories("${PROJECT_SOURCE_DIR}/lib/src/openssl/")
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
set(CMAKE_VERBOSE_MAKEFILE 1)
set(SEED_FILE_PATH "\"${CMAKE_INSTALL_PREFIX}/etc/.encrypt_api_keyfile\"")
add_definitions("-std=c++11")
add_definitions("-g -O2")
add_definitions("-DSEED_FILE_PATH=${SEED_FILE_PATH}")
link_directories(${OPENSSL_LIBDIR})
set(SRCS_OPENSSL openssl/encrypter_openssl.cpp  openssl/encrypter_openssl_aes256cbc.cpp openssl/encrypter_openssl_aria128cbc.cpp openssl/encrypter_openssl_camellia256cbc.cpp openssl/encrypter_openssl_chacha20.cpp openssl/encrypter_openssl_chacha20_poly1305.cpp openssl/encrypter_openssl_seed.cpp openssl/encrypter_openssl_buffer.cpp  openssl/encrypter_openssl_register.cpp )
add_library(encrypt_api SHARED encrypt_api.cpp encrypter_factory.cpp encrypter_seed.cpp ${SRCS_OPENSSL})
target_link_libraries(encrypt_api "-Wl,--version-script,${PROJECT_SOURCE_DIR}/lib/src/encrypt_api.map")
target_link_libraries(encrypt_api crypto)
set_target_properties(encrypt_api PROPERTIES PUBLIC_HEADER ${PROJECT_SOURCE_DIR}/lib/include/encrypt_api.h)
install(TARGETS encrypt_api
	EXPORT encrypt_api-export
	LIBRARY DESTINATION lib
	PUBLIC_HEADER  DESTINATION include)

install(EXPORT encrypt_api-export
    FILE encrypt_api-config.cmake
    DESTINATION share/cmake/encrypt_api/
    )
