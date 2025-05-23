// Tested with OpenSSL version 3.2.1
#include "encryption.h"

SSL_CTX *create_ssl_context(void)
{
    const SSL_METHOD *method = NULL;
    SSL_CTX *ctx             = NULL;

    SSL_library_init();
    OpenSSL_add_all_algorithms(); // TODO: Is this... bad?
    SSL_load_error_strings();

    method = TLS_server_method();
    ctx    = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
    }
    return ctx;
}

int configure_ssl_context(SSL_CTX *ctx)
{
    int er = 0;
    SSL_CTX_set_ecdh_auto(ctx, 1);
    // Load certificate and private key
    if (0 >= SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        er = -1;
    }
    if (0 >= SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        er = -1;
    }
    return er;
}
