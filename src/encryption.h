#ifndef BB_ENCRYPTION
#define BB_ENCRYPTION

// Tested with OpenSSL version 3.2.1
#include <openssl/ssl.h>
#include <openssl/err.h>

SSL_CTX *createSSLContext    ();
void     configureSSLContext (SSL_CTX *ctx);

#endif
