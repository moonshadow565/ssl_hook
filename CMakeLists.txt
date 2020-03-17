cmake_minimum_required(VERSION 3.5)

project(ssl_hook LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(minhook)
add_library(ssl_hook SHARED main.cpp)
target_link_libraries(ssl_hook PRIVATE minhook)
if(WIN32)
    target_link_libraries(ssl_hook PRIVATE ws2_32)
endif()
