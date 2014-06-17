#include<openssl/ssl.h>
#include<sys/types.h>
#include<unistd.h>
#include<stdlib.h>
#include<limits.h>
#include<inttypes.h>
#include<sys/wait.h>
#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include"sockutils.h"

#define MYPATH_MAX 512
#define STRSIZE 1024

typedef struct {
    SSL *ssl;
    SSL_CTX *ctx;
    char *key_file;
    char *crt_file;
    char *chain_file;
    int server_fd;
    int client_fd;
} sslcontainer_t;

int bury_zombies() {
    int nzombies = 0;
    pid_t zombie_pid;
    while (waitpid(-1, NULL, WNOHANG) > 0) nzombies++;
    return nzombies;
}

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

int init_ssl_ctx(sslcontainer_t *cnt) {
    cnt->ctx = SSL_CTX_new(SSLv23_server_method());
    char full_key_path[MYPATH_MAX + 1];
    char full_crt_path[MYPATH_MAX + 1];
    char full_chain_path[MYPATH_MAX + 1];
    char *temp_str;
    char error_str[STRSIZE + 1];
    long new_ssl_mode = 0;
    long ssl_mode;
    if (cnt->ctx == NULL) {
        fprintf(stderr, "Error creating ctx for SSL\n");
        return -1;
    }
    cnt->ssl = SSL_new(cnt->ctx);
    if (cnt->ssl == NULL) {
        fprintf(stderr, "Error creating SSL object\n");
        return -1;
    }
    expand_path(full_key_path, cnt->key_file, MYPATH_MAX);
    expand_path(full_crt_path, cnt->crt_file, MYPATH_MAX);
    if (SSL_CTX_use_PrivateKey_file(cnt->ctx, full_key_path, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Error loading keyfile\n%s\n", show_error(error_str, STRSIZE));
        return -1;
    }
    if (SSL_CTX_use_certificate_file(cnt->ctx, full_crt_path, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "error loading certificate file\n%s\n", show_error(error_str, STRSIZE));
        return -1;
    }
    if (expand_path(full_chain_path, cnt->chain_file, MYPATH_MAX) >= 0) {
        if (SSL_CTX_use_certificate_chain_file(cnt->ctx, full_chain_path) != 1) {
            fprintf(stderr, "Error loading chain file\n%s\n", show_error(error_str, STRSIZE));
            return -1;
        }
    }
    new_ssl_mode = SSL_set_mode(cnt->ssl, SSL_MODE_AUTO_RETRY);
    ssl_mode_str(&temp_str, new_ssl_mode);
    fprintf(stderr, "SSL mode = %s\n", temp_str);
    free(temp_str);
    return 0;
}

int usage(char *prog) {
    fprintf(stderr, "usage is %s <ip> <port> <key> <crt file> [chain file]\n", prog);
    return 0;
}

int start_server_socket(sslcontainer_t *cnt, struct addrinfo *addrs) {
    int sock_fd = socket(addrs->ai_family, addrs->ai_socktype, addrs->ai_protocol);
    if (sock_fd == -1) {
        return -1;
    }
    if (bind(sock_fd, addrs->ai_addr, addrs->ai_addrlen) != 0) {
        perror("Can't bind to port");
        return -1;
    }
    if (listen(sock_fd, 10) != 0) {
        fprintf(stderr, "Error listening to socket\n");
        return -1;
    }
    cnt->server_fd = sock_fd;
    return 0;
}

int handle_client(sslcontainer_t *cnt) {
    BIO *b;
    BIO *sni_b;
    char *buff;
    char *msg;
    char buff_in[STRSIZE + 1];
    char error_str[STRSIZE + 1];
    char *fmt;
    char *sni = NULL;
    int msg_len = 0;
    int nread = 0;
    int nwrote = 0;
    int nbytes = 0;
    int ac = 0;
    int ec = 0;
    if (init_ssl_ctx(cnt) < 0) {
        return -1;
    };

    fprintf(stderr, "Initializing new SSL obect\n");
    // intialize SSL object
    b = BIO_new(BIO_s_mem());
    if (b == NULL) {
        fprintf(stderr, "Error allocating BIO memory object\n");
        SSL_CTX_free(cnt->ctx);
        return -1;
    }
    sni_b = BIO_new(BIO_s_mem());
    if (sni_b == NULL) {
        fprintf(stderr, "Error allocating BIO memory object for SNI header\n");
        SSL_CTX_free(cnt->ctx);
        BIO_free(b);
    }
    cnt->ssl = SSL_new(cnt->ctx);
    if (cnt->ssl == NULL) {
        show_error(error_str, STRSIZE);
        fprintf(stderr, "Error creating SSL object: %s\n", error_str);
        SSL_CTX_free(cnt->ctx);
        BIO_free(sni_b);
        BIO_free(b);

        return -1;
    }
    fprintf(stderr, "Attaching client socket[%i] to SSL object\n", cnt->client_fd);
    if (SSL_set_fd(cnt->ssl, cnt->client_fd) == 0) {
        show_error(error_str, STRSIZE);
        fmt = "Error associating client socket %i with SSL object\n";
        fprintf(stderr, fmt, cnt->client_fd);
        BIO_free(b);
        BIO_free(sni_b);
        SSL_CTX_free(cnt->ctx);
        SSL_free(cnt->ssl);
        return -1;
    }

    fprintf(stderr, "Initializing ssl connection via SSL_accept\n");
    ac = SSL_accept(cnt->ssl);
    if (ac != 1) {
        ec = SSL_get_error(cnt->ssl, ac);
        ssl_error_str(error_str, STRSIZE, ec);
        fprintf(stderr, "Error accepting TLS connection: %s:", error_str);
        show_error(error_str, STRSIZE);
        fprintf(stderr, "%s\n", error_str);
        SSL_CTX_free(cnt->ctx);
        BIO_free(sni_b);
        SSL_free(cnt->ssl);
        BIO_free(b);
        return -1;
    }
    fprintf(stderr, "SSL_accept(ssl) = %i\n", ac);
    fprintf(stderr, "Client connection accepted on socket[%i]\n", cnt->client_fd);

    fprintf(stderr, "retreiving SNI header\n");
    sni = (char *) SSL_get_servername(cnt->ssl, TLSEXT_NAMETYPE_host_name);
    BIO_printf(sni_b, "<body><html>SNI = %s</html></body>\r\n", sni);
    BIO_flush(sni_b);
    drain_bio(sni_b, &msg);
    msg_len = strlen(msg);

    BIO_printf(b, "HTTP/1.1 200 OK\r\n");
    BIO_printf(b, "content-type: text/html\r\n");
    BIO_printf(b, "content-length: %i\r\n", msg_len);
    BIO_printf(b, "\r\n");
    BIO_printf(b, "%s", msg);
    BIO_flush(b);

    fprintf(stderr, "sleeping for %i seconds\n", 2);
    //sleep(2);
    fprintf(stderr, "getting ready to read %i from client socket[%i]\n", STRSIZE, cnt->client_fd);

    nread = SSL_read(cnt->ssl, buff_in, STRSIZE);
    if (nread < 0) {
        show_error(error_str, STRSIZE);
        fprintf(stderr, "Error reading %i bytes from socket[%i]:%s\n", nread, cnt->client_fd, error_str);
        SSL_CTX_free(cnt->ctx);
        BIO_free(b);
        SSL_free(cnt->ssl);
        return -1;
    } else {
        buff_in[nread] = '\0';
    }
    fprintf(stderr, "read %i bytes from socket[%i]\n", nread, cnt->client_fd);
    fwrite(buff_in, nread, 1, stderr);
    nbytes = drain_bio(b, &buff);
    fprintf(stderr, "Getting ready to write %i bytes to socket[%i]\n", nbytes, cnt->client_fd);

    fprintf(stderr, "Write:\n");
    fwrite(buff, nbytes, 1, stderr);
    fflush(stderr);
    nwrote = SSL_write(cnt->ssl, buff, nbytes);
    fprintf(stderr, "wrote %i bytes to socket[%i]\n", nwrote, cnt->client_fd);
    //char *sni_host = SSL_get_servername(cnt->ssl,TLSEXT_NAMETYPE_host_name);
    SSL_shutdown(cnt->ssl);
    free(buff);
    BIO_free(b);
    SSL_free(cnt->ssl);
    SSL_CTX_free(cnt->ctx);

    return 0;
}

int main(int argc, char **argv) {
    sslcontainer_t cnt;
    struct addrinfo *addrinfos;
    struct sockaddr client_addr;
    socklen_t client_addr_len;
    char client_ip[STRSIZE + 1];
    char client_port[STRSIZE + 1];
    char *server_ip;
    char *port;
    char *key;
    char *crt;
    char *chain;
    pid_t cpid;
    uint16_t found_port;
    int client_fd;
    if (argc < 5) {
        usage(argv[0]);
        return -1;
    }
    server_ip = argv[1];
    port = argv[2];
    key = argv[3];
    crt = argv[4];
    chain = NULL;
    if (argc >= 6) {
        chain = argv[5];
    }
    fprintf(stderr, "pid = %i\n", getpid());
    fprintf(stderr, "ppid = %i\n", getppid());
    fprintf(stderr, "Initializing SSL library\n");
    init_ssl_lib();
    cnt.key_file = key;
    cnt.crt_file = crt;
    cnt.chain_file = chain;

    if (lookup(server_ip, port, AF_UNSPEC, &addrinfos) != 0) {
        fprintf(stderr, "Error in lookup\n");
        return 0;
    }
    getipaddrstr(addrinfos, client_ip, &found_port, STRSIZE);
    fprintf(stderr, "Attempting to bind to socket %s:%i\n", client_ip, found_port);
    if (start_server_socket(&cnt, addrinfos) < 0) {
        fprintf(stderr, "Unable to start server socket\n");
        return 0;
    };

    // Start fork loop
    for (;;) {
        fprintf(stderr, "\n\n");
        fprintf(stderr, "Waiting for connection\n");
        client_fd = accept(cnt.server_fd, &client_addr, &client_addr_len);
        if (client_fd == -1) {
            perror("Error accepting client connection:");
            continue;
        }
        fprintf(stderr, "Connection received. client_fd[%i]: ", client_fd);
        if (getnameinfo(&client_addr, client_addr_len, client_ip, STRSIZE,
                client_port, STRSIZE, NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
            fprintf(stderr, "Error getting hostaddr info for new client connection\n");
        } else {

            fprintf(stderr, "%s:%s\n", client_ip, client_port);
        }
        fprintf(stderr, "reaped %i zombies forking for client connection\n", bury_zombies());
        cnt.client_fd = client_fd;
        //        handle_client(&cnt);
        //        close(cnt.client_fd);

        cpid = fork();
        switch (cpid) {
            case -1:
                perror("Fork error server exiting:");
                return -1;
                break;
            case 0:
                // Child processes should close
                // server descriptor and run SSL code
                if (handle_client(&cnt) < 0) {
                    fprintf(stderr, "ssl client failed moving on\n");
                }
                close(cnt.client_fd);
                exit(0);
                break;
            default:
                // Server should close client descriptor and wait for
                // another connection
                fprintf(stderr, "Server: Closing client_fd[%i]\n", client_fd);
                close(cnt.client_fd);
                break;
        }
    }
    return 0;
}
