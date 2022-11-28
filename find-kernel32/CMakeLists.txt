cmake_minimum_required(VERSION 3.0)
project(find-kernel32)
file(GLOB SOURCES src/*.c)
add_library(find-kernel32 SHARED ${SOURCES})
