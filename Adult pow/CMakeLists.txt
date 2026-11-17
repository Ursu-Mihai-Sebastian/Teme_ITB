cmake_minimum_required(VERSION 4.1)
project(tema4IBT)

set(CMAKE_C_STANDARD 11)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(tema4IBT client.c
)

target_compile_options(tema4IBT PRIVATE -O3 -march=native -fopenmp)
target_link_options(tema4IBT PRIVATE -fopenmp)
target_link_libraries(tema4IBT PRIVATE ws2_32)