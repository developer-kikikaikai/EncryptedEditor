cmake_minimum_required(VERSION 2.8)
set(CMAKE_VERBOSE_MAKEFILE 1)
#add_definitions("-g -O0")
add_executable(encrypted_vim encrypt_vim.c main.c)
find_package(encrypt_api REQUIRED)
#if(encrypt_api_FOUND)
#message(STATUS "*** dump start cmake variables ***")
#get_cmake_property(_variableNames VARIABLES)
#foreach(_variableName ${_variableNames})
#        message(STATUS "${_variableName}=${${_variableName}}")
#endforeach()
#message(STATUS "*** dump end ***")
#endif(encrypt_api_FOUND)
target_link_libraries(encrypted_vim encrypt_api)
INSTALL(TARGETS encrypted_vim RUNTIME DESTINATION bin)
