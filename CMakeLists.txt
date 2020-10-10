cmake_minimum_required(VERSION 3.17)
project(md5)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_executable(md5
        md5.cpp
        md5.h
        test.cpp)
