cmake_minimum_required(VERSION 3.16)

option(PKEET_USE_SYSTEM_OPENSSL "Link the system OpenSSL (>= 3.0) found by find_package instead of PKEET_OPENSSL_ROOT" OFF)
set(PKEET_OPENSSL_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/out/install" CACHE PATH "OpenSSL install prefix (static libcrypto.a + headers)")

project(PKEET_FDA_Revisited LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_BUILD_TYPE "" CACHE STRING "" FORCE)
set(PKEET_CXX_FLAGS -O2)
string(JOIN " " PKEET_CXX_FLAGS_STRING ${PKEET_CXX_FLAGS})

find_package(Threads REQUIRED)

if(PKEET_USE_SYSTEM_OPENSSL)
    find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
    message(STATUS "PKEET OpenSSL: system ${OPENSSL_VERSION} (${OPENSSL_CRYPTO_LIBRARY})")
    set(PKEET_OPENSSL_CRYPTO_TARGET OpenSSL::Crypto)
else()
    set(PKEET_OPENSSL_INCLUDE_DIR "${PKEET_OPENSSL_ROOT}/include")
    set(PKEET_OPENSSL_CRYPTO_LIB  "${PKEET_OPENSSL_ROOT}/lib/libcrypto.a")

    foreach(_f ${PKEET_OPENSSL_CRYPTO_LIB} ${PKEET_OPENSSL_INCLUDE_DIR}/openssl/evp.h ${PKEET_OPENSSL_INCLUDE_DIR}/openssl/opensslv.h)
        if(NOT EXISTS ${_f})
            message(FATAL_ERROR "Missing ${_f}\nRun ./build.sh deps first.")
        endif()
    endforeach()

    file(STRINGS "${PKEET_OPENSSL_INCLUDE_DIR}/openssl/opensslv.h" _ossl_version_line REGEX "^# *define OPENSSL_VERSION_TEXT")
    message(STATUS "PKEET OpenSSL: ${PKEET_OPENSSL_ROOT} (${_ossl_version_line})")

    add_library(PKEET::Crypto STATIC IMPORTED)
    set_target_properties(PKEET::Crypto PROPERTIES
        IMPORTED_LOCATION ${PKEET_OPENSSL_CRYPTO_LIB}
        INTERFACE_INCLUDE_DIRECTORIES ${PKEET_OPENSSL_INCLUDE_DIR}
        INTERFACE_LINK_LIBRARIES "Threads::Threads;${CMAKE_DL_LIBS}")
    set(PKEET_OPENSSL_CRYPTO_TARGET PKEET::Crypto)
endif()

add_library(pkeet STATIC
    src/Group.cpp
    src/LGZ22.cpp
    src/ModifiedPKEETFDA.cpp
)
target_include_directories(pkeet PUBLIC src)
target_link_libraries(pkeet PUBLIC ${PKEET_OPENSSL_CRYPTO_TARGET} Threads::Threads)
target_compile_options(pkeet PUBLIC ${PKEET_CXX_FLAGS} -Wall -Wextra)

add_executable(pkeet_test src/Tests.cpp)
target_link_libraries(pkeet_test PRIVATE pkeet)

add_executable(pkeet_bench src/Bench.cpp)
target_link_libraries(pkeet_bench PRIVATE pkeet)
target_compile_definitions(pkeet_bench PRIVATE PKEET_CXX_FLAGS="${PKEET_CXX_FLAGS_STRING}")
