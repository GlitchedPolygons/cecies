cmake_minimum_required(VERSION 3.15)
project(cecies C)

set(CMAKE_C_STANDARD 11)

add_library(${PROJECT_NAME} library.c library.h)