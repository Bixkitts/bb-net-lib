#ifndef BB_ENCRYPTION
#define BB_ENCRYPTION

// Tested with OpenSSL version 3.2.1
#include <openssl/ssl.h>
#include <openssl/err.h>

SSL_CTX *create_ssl_context    ();
void     configure_ssl_context (SSL_CTX *ctx);

#endif
