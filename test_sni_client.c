#include<stdio.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<openssl/ssl.h>
#include<openssl/err.h>
#include<openssl/bio.h>
#include<openssl/x509.h>
#include<inttypes.h>
#include<string.h>
#include<netdb.h>
#include<unistd.h>
#include"sockutils.h"

#define ERRORSTRSIZE 256
#define IPSTRSIZE 40
#define AFFAMILYSTRSIZE 64
#define STRSIZE 256
#define BUFFSIZE 1024

typedef struct {
    SSL_CTX *ctx;
    SSL *ssl;
    int fd;
    struct addrinfo *addrs;
    X509 *peer_crt;
    STACK_OF(X509) *peer_chain;
} sslcontainer_t;

int usage(char *prog) {
    printf("usage is %s <sni hostname> <target host> <port> [ipv4|ipv5|any]\n",
            prog);
    return -1;
}

char *show_error(char *out, size_t size) {
    unsigned long err_num = ERR_get_error();
    ERR_error_string_n(err_num, out, size);
    return out;
}

int drain_bio(BIO *b, char **data) {
    char *str_out;
    int str_size;
    str_size = BIO_ctrl_pending(b);
    str_out = (char *) malloc(sizeof (char) *(str_size + 1));
    if (str_out == NULL) {
        return -1;
    }
    str_out[str_size] = '\0';
    BIO_read(b, str_out, str_size);
    *data = str_out;
    return str_size;
}

int connect_ssl(sslcontainer_t *cnt) {
    int ssl_connect_resp;
    char err_str[ERRORSTRSIZE + 1];
    char *fmt;
    if (SSL_set_fd(cnt->ssl, cnt->fd) != 1) {
        printf("Error wrapping ssl around socket descriptor %i\n", cnt->fd);
        return -1;
    }
    ssl_connect_resp = SSL_connect(cnt->ssl);
    if (ssl_connect_resp != 1) {
        fmt = "TLS Handshake failed: %s\n";
        printf(fmt, show_error(err_str, ERRORSTRSIZE));
        return -1;
    } else if (ssl_connect_resp < 0) {
        fmt = "Protocol failure attmpting TLS handshake: %s";
        printf(fmt, show_error(err_str, ERRORSTRSIZE));
        return -1;
    }
    // Fetching peer crt and chain
    cnt->peer_chain = SSL_get_peer_cert_chain(cnt->ssl);
    cnt->peer_crt = SSL_get_peer_certificate(cnt->ssl);
    return 0;
}

int init_ssl_ctx(sslcontainer_t *cnt, char *sni_host) {
    cnt->ctx = SSL_CTX_new(SSLv23_client_method());
    if (cnt->ctx == NULL) {
        printf("Error creating ctx for SSL\n");
        return -1;
    }
    cnt->ssl = SSL_new(cnt->ctx);
    if (cnt->ssl == NULL) {
        printf("Error creating SSL object\n");
    }
    SSL_set_tlsext_host_name(cnt->ssl, sni_host);
    SSL_set_mode(cnt->ssl, SSL_MODE_AUTO_RETRY);
    return 0;
}

int main(int argc, char **argv) {
    sslcontainer_t cnt;
    BIO *b = BIO_new(BIO_s_mem());
    char *parsed_x509;
    char *buff;
    char ip[IPSTRSIZE];
    char ai_family_str[AFFAMILYSTRSIZE + 1];
    char *fmt;
    struct addrinfo *addrs;
    int ai_family;
    char *sni_host;
    char *target_host;
    char *service;
    uint16_t port;
    int sock_fd;
    int ip_num = 0;
    int nbytes;
    int ec;
    printf("size of sslcontainer_t = %zi\n", sizeof (sslcontainer_t));
    printf("size of X509 = %zi\n", sizeof (X509));
    if (argc < 4) {
        usage(argv[0]);
        return -1;
    }
    ai_family = (argc >= 5) ? get_ai_family(argv[4]) : AF_UNSPEC;
    sni_host = argv[1];
    target_host = argv[2];
    service = argv[3];
    printf("looking up %s %s: ", target_host, service);
    if (lookup(target_host, service, ai_family, &addrs) != 0) {
        printf("Error in lookup\n");
        return 0;
    }
    if (addrs == NULL) {
        printf("error lookup up yielded empty response\n");
        return -1;
    }
    getipaddrstr(addrs, ip, &port, IPSTRSIZE);
    affamily2str(ai_family_str, AFFAMILYSTRSIZE, addrs->ai_family);
    fmt = "found host {af_family=%s ip=%s port=%i\n";
    printf(fmt, ai_family_str, ip, port);
    // Must init the OpenSSL library
    printf("initializeing CTX context\n");
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    if (init_ssl_ctx(&cnt, sni_host) < 0) {
        printf("Error creating SSL context\n");
        return -1;
    }
    printf("Opening socket to %s: %i\n", ip, port);
    fflush(stdout);
    sock_fd = connect_socket(addrs, &ip_num);
    if (sock_fd < 0) {
        printf("Error connecting socket\n");
        return -1;
    }
    printf("socket connected on fd %i\n", sock_fd);
    cnt.fd = sock_fd;
    if (connect_ssl(&cnt) < 0) {
        printf("Error wrapping SSL around socket\n");
        return 0;
    }
    printf("SSL socket wraped\n");
    if (decodeX509(&parsed_x509, cnt.peer_crt) < 0) {
        printf("Error decoding x509\n");
    }
    printf("Main Crt:\n%s\n", parsed_x509);
    X509_free(cnt.peer_crt);
    free(parsed_x509);
    if (decodeX509Chain(&parsed_x509, cnt.peer_chain) < 0) {
        printf("Error decoding cert chain\n");
        return 0;
    }
    printf("%s\n", parsed_x509);
    free(parsed_x509);
    BIO_printf(b, "GET / HTTP/1.1\r\n");
    BIO_printf(b, "HOST: %s\r\n\r\n", sni_host);
    BIO_flush(b);
    nbytes = drain_bio(b, &buff);
    SSL_write(cnt.ssl, buff, nbytes);
    free(buff);
    buff = (char *) malloc(sizeof (char) *(BUFFSIZE + 1));
    if (buff == NULL) {
        printf("Error allocating %i bytes for recieve buffer\n", BUFFSIZE + 1);
        return -1;
    }
    printf("Closing write end of socket\n");
    if (SSL_shutdown(cnt.ssl) == 0) {
        shutdown(cnt.fd, SHUT_WR);
        printf("low level socket write end closed\n");
    };
    for (;;) {
        nbytes = SSL_read(cnt.ssl, buff, BUFFSIZE);
        if (nbytes <= 0) {
            ec = SSL_get_error(cnt.ssl, nbytes);
            switch (ec) {
                case SSL_ERROR_NONE:
                    buff[nbytes] = '\0';
                    printf("%s\n", buff);
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    return 0; // Remote end closed
                    break;
                case SSL_ERROR_WANT_READ:
                    printf("WANT_READ\n");
                    break;
                case SSL_ERROR_WANT_WRITE:
                    printf("WANT_WRITE\n");
                    break;
                default:
                    printf("got error code %i\n", ec);
                    return 0;
                    break;
            }
        } else {
            buff[nbytes] = '\0';
            printf("%s", buff);
            fflush(stdout);
        }
    }
    SSL_free(cnt.ssl);
    SSL_CTX_free(cnt.ctx);
    free(buff);
    return 0;
}
