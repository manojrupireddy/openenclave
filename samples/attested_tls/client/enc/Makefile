# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../../config.mk

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oeenclave-$(C_COMPILER) --variable=includedir)

.PHONY: all build clean run

all:
	$(MAKE) build
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../tls_client.edl --trusted --trusted-dir . \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -I.  -std=c++11 ecalls.cpp mbedtls_client.cpp cert_verify_config.cpp ../../common/cert_verifier.cpp ../../common/identity_verifier.cpp ../../common/utility.cpp ../../common/mbedtls_utility.cpp
	$(CC) -c $(CFLAGS) $(CINCLUDES) -I. ./tls_client_t.c
	$(CXX) -o tls_client_enclave ecalls.o mbedtls_client.o cert_verify_config.o cert_verifier.o identity_verifier.o utility.o mbedtls_utility.o tls_client_t.o $(LDFLAGS) -lmbedtls -lmbedcrypto -loehostsock -loehostresolver -loecore -loelibc -loesyscall

sign:
	oesign sign -e tls_client_enclave -c  enc.conf -k private.pem

clean:
	rm -f ./*.o tls_client_enclave tls_client_enclave.signed enclave1.signed.so tls_client_t.* tls_client_args.h
