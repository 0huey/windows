cmake_minimum_required(VERSION 3.0)
project(inject-pe)
file(GLOB SOURCES src/*.c)
add_executable(inject-pe ${SOURCES})
