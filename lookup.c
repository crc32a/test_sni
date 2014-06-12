#include<stdio.h>
#include"sockutils.h"

#define AF_STRSIZE 256
#define HOSTSIZE 256
#define IPSTRSIZE 40

int usage(char *prog) {
    printf("usage is %s <ipv4|ipv6|any> <host> [port]\n", prog);
    return -1;
}

int main(int argc, char **argv) {
    struct addrinfo *lookup_response;
    struct addrinfo *curr;
    socklen_t sock_size;
    char ip[IPSTRSIZE];
    char ai_family_str[AF_STRSIZE + 1];
    ;
    char *host;
    char *service = NULL;
    int ai_family;
    int lookup_rc;
    in_port_t found_port;
    char *fmt;
    int i;
    if (argc < 3) {
        usage(argv[0]);
        return -1;
    }
    ai_family = get_ai_family(argv[1]);
    host = argv[2];
    service = (argc >= 4) ? argv[3] : NULL;

    fmt = "lookup(%s,%s,%i,&lookup_response) = ";
    printf(fmt, host, service, ai_family);
    fflush(stdout);
    lookup_rc = lookup(host, service, ai_family, &lookup_response);
    printf("%i\n", lookup_rc);
    curr = lookup_response;
    if (curr == NULL) {
        printf("Not found\n");
        return -1;
    }
    i = 0;
    while (curr != NULL) {
        sock_size = curr->ai_addrlen;
        ai_family = curr->ai_family;
        getipaddrstr(curr, ip, &found_port, IPSTRSIZE);
        affamily2str(ai_family_str, AF_STRSIZE, ai_family);
        fmt = "ip[%3i] = {ai_family= %s ip = %s port = %i}\n";
        printf(fmt, i, ai_family_str, ip, found_port);
        curr = curr->ai_next;
        i++;
    }
    return 0;
}

