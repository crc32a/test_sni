#include<sys/types.h>
#include<sys/socket.h>
#include<stdio.h>
#include<netdb.h>
#include<string.h>
#include"sockutils.h"
#include<arpa/inet.h>
#include<ctype.h>
#include<unistd.h>
#define STRSIZE 1024

int strnlower(char *dst, char *src, size_t n) {
    int i;
    for (i = 0; i < n; i++) {
        if (*src == '\0') {
            *dst = '\0';
            return 0;
        }
        *dst = tolower((unsigned char) *src);
        src++;
        dst++;
    }
    *dst = '\0';
    return 0;
}

int getipaddrstr(struct addrinfo *ai, char *hname, uint16_t *port, socklen_t buffsize) {
    struct sockaddr_in *sa4;
    struct sockaddr_in6 *sa6;
    switch (ai->ai_family) {
        case AF_INET:
            sa4 = (struct sockaddr_in *) ai->ai_addr;
            if (port != NULL) *port = ntohs(sa4->sin_port);
            if (inet_ntop(AF_INET, &(sa4->sin_addr), hname, buffsize) != 0) {
                return -1;
            }
            return 0;
            ;
        case AF_INET6:
            sa6 = (struct sockaddr_in6 *) ai->ai_addr;
            if (port != NULL) *port = ntohs(sa6->sin6_port);
            if (inet_ntop(AF_INET6, &(sa6->sin6_addr), hname, buffsize) != 0) {
                return -1;
            }
            return 0;
        default:
            strncpy(hname, "ERROR", buffsize);
            return -1;
    }
}

int connect_socket(struct addrinfo *addrs, int *ip_i) {
    struct addrinfo *curr = addrs;
    int fd;
    int addr_num = 0;
    while (curr != NULL) {
        fd = socket(curr->ai_family, curr->ai_socktype, curr->ai_protocol);
        if (fd == -1) {
            return -1;
        }
        if (connect(fd, curr->ai_addr, curr->ai_addrlen) != 0) {
            close(fd);
            fd = -1;
            curr = curr->ai_next;
            addr_num++;
            continue;
        }
        *ip_i = addr_num;
        return fd;
    }
    *ip_i = -1;
    return -1;
}

int affamily2str(char *buff, size_t buffsize, int af) {
    switch (af) {
        case AF_UNSPEC:
            strncpy(buff, "AF_UNSPEC", buffsize);
            break;
        case AF_LOCAL:
            strncpy(buff, "AF_LOCAL||AF_UNIX||AF_FILE", buffsize);
            break;
        case AF_INET:
            strncpy(buff, "AF_INET", buffsize);
            break;
        case AF_IPX:
            strncpy(buff, "AF_IPX", buffsize);
            break;
        case AF_APPLETALK:
            strncpy(buff, "AF_APPLETALK", buffsize);
            break;
        case AF_INET6:
            strncpy(buff, "AF_INET6", buffsize);
            break;
        case AF_DECnet:
            strncpy(buff, "AF_DECnet", buffsize);
            break;
        case AF_SNA:
            strncpy(buff, "AF_SNA", buffsize);
            break;
        case AF_MAX:
            strncpy(buff, "AF_MAX", buffsize);
            break;
        default:
            strncpy(buff, "UNKNOWN", buffsize);
            break;
    }
    return 0;
}

int lookup(char *host, char *service, int ai_family, struct addrinfo **result) {
    int rc;
    struct addrinfo hints;
    memset(&hints, 0, sizeof (struct addrinfo));
    hints.ai_flags = 0;
    hints.ai_protocol = 0;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = ai_family;

    rc = getaddrinfo(host, service, &hints, result);
    return rc;
}

int get_ai_family(char *ai_family_strin) {
    char ai_family_str[STRSIZE + 1];
    strnlower(ai_family_str, ai_family_strin, STRSIZE);
    if (strncmp(ai_family_str, "ipv4", STRSIZE) == 0) {
        return AF_INET;
    } else if (strncmp(ai_family_str, "ipv6", STRSIZE) == 0) {
        return AF_INET6;
    } else {
        return AF_UNSPEC;
    }
}

int get_ai_socktype(char *ai_socktype_strin) {
    char ai_socktype_str[STRSIZE + 1];
    strnlower(ai_socktype_str, ai_socktype_strin, STRSIZE);
    if (strncmp(ai_socktype_str, "tcp", STRSIZE) == 0) {
        return SOCK_STREAM;
    } else if (strncmp(ai_socktype_str, "udp", STRSIZE) == 0) {
        return SOCK_DGRAM;
    } else {
        return -1;
    }
}

int printaddrinfos(struct addrinfo *ai, FILE *fp) {
    struct addrinfo *curr = ai;
    char host[STRSIZE + 1];
    in_port_t p;
    while (curr != NULL) {
        getipaddrstr(curr, host, &p, STRSIZE + 1);
        printaddrinfo(curr, host, NULL, &p, fp);
        curr = curr->ai_next;
    }
    return 0;
}

int printaddrinfo(struct addrinfo *ai, char *hname, char *sname, in_port_t *port, FILE *fp) {
    char ai_familystr[STRSIZE + 1];
    char ai_socktypestr[STRSIZE + 1];
    char ai_protocolstr[STRSIZE + 1];
    char host[STRSIZE + 1];
    char serv[STRSIZE + 1];

    affamily2str(ai_familystr, STRSIZE, ai->ai_family);
    socktype2str(ai_socktypestr, STRSIZE, ai->ai_socktype);
    protocol2str(ai_protocolstr, STRSIZE, ai->ai_protocol);
    fprintf(fp, "{ ");
    fprintf(fp, "ai_flags=%i ", ai->ai_flags);
    fprintf(fp, "ai_family=%i(%s) ", ai->ai_family, ai_familystr);
    fprintf(fp, "ai_socktype=%i(%s) ", ai->ai_socktype, ai_socktypestr);
    fprintf(fp, "ai_protocol=%i(%s) ", ai->ai_protocol, ai_protocolstr);
    fprintf(fp, "ai_addrlen=%i ", ai->ai_addrlen);
    fprintf(fp, "ai_cannonname=%s ", ai->ai_canonname);
    if (hname != NULL && strcmp(hname, "") != 0) {
        fprintf(fp, "host=\"%s\" ", hname);
    }
    if (sname != NULL && strcmp(sname, "") != 0) {
        fprintf(fp, "serv=\"%s\" ", sname);
    }

    if (port != NULL) {
        fprintf(fp, "port=%i ", *port);
    }
    fprintf(fp, "}\n");
    return 0;
}

int socktype2str(char *buff, size_t buffsize, int st) {
    switch (st) {
        case SOCK_STREAM:
            strncpy(buff, "SOCK_STREAM", buffsize);
            break;
        case SOCK_DGRAM:
            strncpy(buff, "SOCK_DGRAM", buffsize);
            break;
        case SOCK_RAW:
            strncpy(buff, "SOCK_RAW", buffsize);
            break;
        case SOCK_RDM:
            strncpy(buff, "SOCK_RDM", buffsize);
            break;
        case SOCK_SEQPACKET:
            strncpy(buff, "SOCK_SEQPACKET", buffsize);
            break;
        default:
            strncpy(buff, "UNKNOWN", buffsize);
            break;
    }
    return 0;
}

int protocol2str(char *buff, size_t buffsize, int pf) {
    switch (pf) {
        case IPPROTO_IP:
            strncpy(buff, "IPPROTO_IP", buffsize);
            break;
        case IPPROTO_ICMP:
            strncpy(buff, "IPPROTO_ICMP", buffsize);
            break;
        case IPPROTO_IGMP:
            strncpy(buff, "IPPROTO_IGMP", buffsize);
            break;
        case IPPROTO_IPIP:
            strncpy(buff, "IPPROTO_IPIP", buffsize);
            break;
        case IPPROTO_TCP:
            strncpy(buff, "IPPROTO_TCP", buffsize);
            break;
        case IPPROTO_EGP:
            strncpy(buff, "IPPROTO_EGP", buffsize);
            break;
        case IPPROTO_PUP:
            strncpy(buff, "IPPROTO_PUP", buffsize);
            break;
        case IPPROTO_UDP:
            strncpy(buff, "IPPROTO_UDP", buffsize);
            break;
        case IPPROTO_IDP:
            strncpy(buff, "IPPROTO_IDP", buffsize);
            break;
        case IPPROTO_TP:
            strncpy(buff, "IPPROTO_TP", buffsize);
            break;
        case IPPROTO_IPV6:
            strncpy(buff, "IPPROTO_IPV6", buffsize);
            break;
        case IPPROTO_ROUTING:
            strncpy(buff, "IPPROTO_ROUTING", buffsize);
            break;
        case IPPROTO_FRAGMENT:
            strncpy(buff, "IPPROTO_FRAGMENT", buffsize);
            break;
        case IPPROTO_RSVP:
            strncpy(buff, "IPPROTO_RSVP", buffsize);
            break;
        case IPPROTO_GRE:
            strncpy(buff, "IPPROTO_GRE", buffsize);
            break;
        case IPPROTO_ESP:
            strncpy(buff, "IPPROTO_ESP", buffsize);
            break;
        case IPPROTO_AH:
            strncpy(buff, "IPPROTO_AH", buffsize);
            break;
        case IPPROTO_ICMPV6:
            strncpy(buff, "IPPROTO_ICMPV6", buffsize);
            break;
        case IPPROTO_NONE:
            strncpy(buff, "IPPROTO_NONE", buffsize);
            break;
        case IPPROTO_DSTOPTS:
            strncpy(buff, "IPPROTO_DSTOPTS", buffsize);
            break;
        case IPPROTO_MTP:
            strncpy(buff, "IPPROTO_MTP", buffsize);
            break;
        case IPPROTO_ENCAP:
            strncpy(buff, "IPPROTO_ENCAP", buffsize);
            break;
        case IPPROTO_PIM:
            strncpy(buff, "IPPROTO_PIM", buffsize);
            break;
        case IPPROTO_RAW:
            strncpy(buff, "IPPROTO_RAW", buffsize);
            break;
    }
    return 0;
}

