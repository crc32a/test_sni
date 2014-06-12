#include<openssl/ssl.h>
#include<sys/types.h>
#include<unistd.h>
#include<stdlib.h>
#include<limits.h>
#include<inttypes.h>
#include<stdio.h>
#include<string.h>
#include"sockutils.h"

#define MYPATH_MAX 512
#define STRSIZE 1024

typedef struct {
    SSL *ssl;
    SSL_CTX *ctx;
    int server_fd;
    int client_fd;
} sslcontainer_t;

char *show_error(char *out, size_t size) {
    unsigned long err_num = ERR_get_error();
    ERR_error_string_n(err_num, out, size);
    return out;
}

int expand_path(char *out, char *in, int n) {
    char *resolved;
    if (in == NULL) {
        return -1;
    }
    resolved = realpath(in, NULL);
    if (resolved == NULL) {
        strncpy(out, in, n);
        return 0;
    }
    strncpy(out, resolved, n);
    free(resolved);
    return 0;
}

int init_ssl_ctx(sslcontainer_t *cnt, char *key_file, char *crt_file, char *chain_file) {
    cnt->ctx = SSL_CTX_new(SSLv23_server_method());
    char full_key_path[MYPATH_MAX + 1];
    char full_crt_path[MYPATH_MAX + 1];
    char full_chain_path[MYPATH_MAX + 1];
    char error_str[STRSIZE + 1];
    if (cnt->ctx == NULL) {
        printf("Error creating ctx for SSL\n");
        return -1;
    }
    cnt->ssl = SSL_new(cnt->ctx);
    if (cnt->ssl == NULL) {
        printf("Error creating SSL object\n");
        return -1;
    }
    expand_path(full_key_path, key_file, MYPATH_MAX);
    expand_path(full_crt_path, crt_file, MYPATH_MAX);
    if (SSL_set_mode(cnt->ssl, SSL_MODE_AUTO_RETRY) != 1) {

    };
    if (SSL_CTX_use_PrivateKey_file(cnt->ctx, full_key_path, SSL_FILETYPE_PEM) != 1) {
        printf("Error loading keyfile\n%s\n", show_error(error_str, STRSIZE));
        return -1;
    }
    if (SSL_CTX_use_certificate_file(cnt->ctx, full_crt_path, SSL_FILETYPE_PEM) != 1) {
        printf("error loading certificate file\n%s\n", show_error(error_str, STRSIZE));
        return -1;
    }
    if (expand_path(full_chain_path, chain_file, MYPATH_MAX) >= 0) {
        if (SSL_CTX_use_certificate_chain_file(cnt->ctx, full_chain_path) != 1) {
            printf("Error loading chain file\n%s\n", show_error(error_str, STRSIZE));
            return -1;
        }
    }
    return 0;
}

int usage(char *prog) {
    printf("usage is %s <ip> <port> <key> <crt file> [chain file]\n", prog);
    return 0;
}

int start_server_socket(sslcontainer_t *cnt, struct addrinfo *addrs) {
    int sock_fd = socket(addrs->ai_family, addrs->ai_socktype, addrs->ai_protocol);
    if (sock_fd == -1) {
        return -1;
    }
    if (bind(sock_fd, (struct sockaddr*) &addrs, sizeof (struct addrinfo)) != 0) {
        perror("Can't bind to port");
        return -1;
    }
    if (listen(sock_fd, 10) != 0) {
        printf("Error listening to socket\n");
        return -1;
    }
    cnt->server_fd = sock_fd;
    return 0;
}

int main(int argc, char **argv) {
    sslcontainer_t cnt;
    struct addrinfo *addrs;
    char tmp_str[STRSIZE + 1];
    char *ip;
    char *port;
    char *key;
    char *crt;
    char *chain;
    uint16_t found_port;
    int client_fd;
    if (argc < 5) {
        usage(argv[0]);
        return -1;
    }
    ip = argv[1];
    port = argv[2];
    key = argv[3];
    crt = argv[4];
    chain = NULL;
    if (argc >= 6) {
        chain = argv[5];
    }
    printf("pid = %i\n", getpid());
    printf("ppid = %i\n", getppid());
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    init_ssl_ctx(&cnt, key, crt, chain);

    if (lookup(ip, port, AF_UNSPEC, &addrs) != 0) {
        printf("Error in lookup\n");
        return 0;
    }
    getipaddrstr(addrs, tmp_str, &found_port, STRSIZE);
    printf("Attempting to bind to socket %s:%i\n", tmp_str, found_port);
    if (start_server_socket(&cnt, addrs) < 0) {
        printf("Unable to start server socket\n");
        return 0;
    };

    client_fd = accept(cnt.server_fd, addrs->ai_addr, &addrs->ai_addrlen);
    return 0;
}
