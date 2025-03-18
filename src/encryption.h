#ifndef BB_ENCRYPTION
#define BB_ENCRYPTION

// Tested with OpenSSL version 3.2.1
#include <openssl/err.h>
#include <openssl/ssl.h>

SSL_CTX *create_ssl_context(void);
int configure_ssl_context(SSL_CTX *ctx);

#endif
