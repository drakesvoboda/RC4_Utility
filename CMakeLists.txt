cmake_minimum_required (VERSION 2.6)
project (my_rc4 C)

# location of header files
include_directories(
    ${PROJECT_SOURCE_DIR}/src
)

file(GLOB SOURCES src/*.c)
list(REMOVE_ITEM SOURCES ${PROJECT_SOURCE_DIR}/src/my_rc4.c)

add_executable(main ${PROJECT_SOURCE_DIR}/src/my_rc4.c)
target_link_libraries(main ${SOURCES})


