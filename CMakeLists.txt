cmake_minimum_required(VERSION 3.20)

project(ssl_hook LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(minhook)
add_library(ssl_hook SHARED src/main.cpp src/ppp.hpp)
target_link_libraries(ssl_hook PRIVATE minhook)
if(WIN32)
    target_compile_definitions(ssl_hook PUBLIC -D_CRT_SECURE_NO_WARNINGS)
    target_link_libraries(ssl_hook PRIVATE ws2_32)
endif()
