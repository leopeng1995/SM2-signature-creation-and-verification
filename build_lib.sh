#!/usr/bin/env bash
rm *.so
gcc -shared -fPIC *.c \
	-I . \
	-L . \
 	/usr/local/opt/openssl@1.1/lib/libcrypto.dylib \
	/usr/local/opt/openssl@1.1/lib/libssl.dylib \
	-o sm_lib.so
