#include<openssl/ssl.h>
#include<openssl/bio.h>
#include<openssl/x509.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netdb.h>
#include<stdio.h>

#ifndef __SOCKUTILS_H
#define __SOCKUTILS_H 1
#endif

int strnlower(char *dst, char *src, size_t n);
int getipaddrstr(struct addrinfo *ai, char *hname, uint16_t *port, socklen_t buffsize);
int affamily2str(char *buff, size_t buffsize, int af);
int lookup(char *host, char *port, int ai_family, struct addrinfo **result);
int get_ai_family(char *ai_family_strin);
int get_ai_socktype(char *ai_socktype_strin);
int printaddrinfos(struct addrinfo *ai, FILE *fp);
int printaddrinfo(struct addrinfo *ai, char *hname, char *sname, in_port_t *port, FILE *fp);
int socktype2str(char *buff, size_t buffsize, int st);
int protocol2str(char *buff, size_t buffsize, int pf);
int connect_socket(struct addrinfo *addrs, int *ip_i);
int decodeX509Chain(char **x509str, STACK_OF(X509) * chain);
int decodeX509(char **x509str, X509 *crt);
int ssl_error_str(char *buff, size_t buffsize, int ec);
int get_long_bits(char *bitsstr, long bits);
int ssl_mode_str(char **buff, long mode);
int drain_bio(BIO *b, char **data);