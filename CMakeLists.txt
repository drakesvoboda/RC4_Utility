cmake_minimum_required (VERSION 2.6)
project (my_rc4 C)

# Search OpenSSL
find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)

if( OPENSSL_FOUND )
    include_directories(${OPENSSL_INCLUDE_DIRS})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
else()
    # Error; with REQUIRED, pkg_search_module() will throw an error by it's own
endif()

# location of header files
include_directories(
    ${PROJECT_SOURCE_DIR}/src
)

file(GLOB SOURCES src/*.c)
list(REMOVE_ITEM SOURCES ${PROJECT_SOURCE_DIR}/src/my_rc4.c)

add_executable(main ${PROJECT_SOURCE_DIR}/src/my_rc4.c)
target_link_libraries(main ${SOURCES} ${OPENSSL_LIBRARIES})


