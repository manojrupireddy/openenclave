# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

project("File Encryptor Sample" LANGUAGES C CXX)

find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)

add_subdirectory(enclave/openssl)
add_subdirectory(host)

# Generate key
add_custom_command(
  OUTPUT private.pem public.pem
  COMMAND openssl genrsa -out private.pem -3 3072
  COMMAND openssl rsa -in private.pem -pubout -out public.pem)

# Sign enclave
add_custom_command(
  OUTPUT enclave/openssl/enclave.signed
  DEPENDS enclave/openssl enclave/openssl/file-encryptor.conf private.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave> -c
          ${CMAKE_SOURCE_DIR}/enclave/openssl/file-encryptor.conf -k private.pem)

add_custom_target(sign ALL DEPENDS enclave/openssl/enclave.signed)

if ((NOT DEFINED ENV{OE_SIMULATION}) OR (NOT $ENV{OE_SIMULATION}))
  add_custom_target(
    run
    DEPENDS file-encryptor_host sign testfile
    COMMAND file-encryptor_host ${CMAKE_CURRENT_SOURCE_DIR}/testfile
            ${CMAKE_BINARY_DIR}/enclave/openssl/enclave.signed)
endif ()

add_custom_target(
  simulate
  DEPENDS file-encryptor_host sign testfile
  COMMAND file-encryptor_host ${CMAKE_CURRENT_SOURCE_DIR}/testfile
          ${CMAKE_BINARY_DIR}/enclave/openssl/enclave.signed --simulate)
