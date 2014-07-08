#include<openssl/ssl.h>
#include<openssl/bio.h>
#include<openssl/x509.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<limits.h>
#include<stdio.h>
#include<netdb.h>
#include<string.h>
#include<arpa/inet.h>
#include<ctype.h>
#include<unistd.h>
#include<errno.h>
#include<time.h>
#include"sockutils.h"

#define STRSIZE 1024
#define CNSTRSIZE 256
#define BUFFSIZE 1024

char bit_vals[] = {'0', '1'};

int read_file(char **buff, int fd) {
    char local_buff[BUFFSIZE + 1];
    char *drain_buff = NULL;
    char *fmt;
    BIO *b;
    int total_bytes = 0;
    int nbytes = 0;
    int drain_bytes = 0;
    b = BIO_new(BIO_s_mem());
    if (b == NULL) {
        return -1;
    }
    for (;;) {
        nbytes = read(fd, local_buff, BUFFSIZE);
        if (nbytes == 0) {
            break;
        }
        if (nbytes < 0) {
            BIO_free(b);
            return -1;
        }
        if (BIO_write(b, local_buff, nbytes) < nbytes) {
            BIO_free(b);
            return -1;
        }
        total_bytes += nbytes;
    }

    drain_bytes = drain_bio(b, &drain_buff);
    if (drain_bytes != total_bytes) {
        fmt = "Erro only got %i bytes but was expecting %i\n";
        fprintf(stderr, fmt, drain_bytes, total_bytes);
        BIO_free(b);
        free(drain_buff);
        return -1;
    }
    *buff = drain_buff;
    BIO_free(b);
    return total_bytes;
}

int expand_path(char *out, char *in, int n) {
    char *resolved;
    if (in == NULL) {
        return -1;
    }
    resolved = realpath(in, NULL);
    if (resolved == NULL) {
        perror("resolved path error:");
        strncpy(out, in, n);
        return 0;
    }
    strncpy(out, resolved, n);
    free(resolved);
    return 0;
}

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

int ssl_error_str(char *error_buff, size_t nbytes, int error_code) {
    switch (error_code) {
        case SSL_ERROR_NONE:
            strncpy(error_buff, "SSL_ERROR_NONE", nbytes);
            break;
        case SSL_ERROR_ZERO_RETURN:
            strncpy(error_buff, "SSL_ERROR_ZERO_RETURN", nbytes);
            break;
        case SSL_ERROR_WANT_READ:
            strncpy(error_buff, "SSL_ERROR_WANT_READ", nbytes);
            break;
        case SSL_ERROR_WANT_WRITE:
            strncpy(error_buff, "SSL_ERROR_WANT_WRITE", nbytes);
            break;
        case SSL_ERROR_WANT_CONNECT:
            strncpy(error_buff, "SSL_ERROR_WANT_CONNECT", nbytes);
            break;
            break;
        case SSL_ERROR_WANT_ACCEPT:
            strncpy(error_buff, "SSL_ERROR_WANT_ACCEPT", nbytes);
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:
            strncpy(error_buff, "SSL_ERROR_WANT_X509_LOOKUP", nbytes);
            break;
        case SSL_ERROR_SYSCALL:
            strncpy(error_buff, "SSL_ERROR_SYSCALL", nbytes);
            break;
        case SSL_ERROR_SSL:
            strncpy(error_buff, "SSL_ERROR_SSL", nbytes);
            break;
        default:
            strncpy(error_buff, "UNKNOWN", nbytes);

    }
    return 0;
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

int decodeX509CN(char *cn, X509 *crt, int useSubject, size_t buff_size) {
    unsigned char *data;
    X509_NAME_ENTRY *ent;
    int loc = 0;
    int i;
    int nbytes;
    char *cn_ptr;
    cn_ptr = cn;
    *cn_ptr = '\0';
    if (crt == NULL) {
        return -1;
    }
    X509_NAME *name;
    if (useSubject) {
        name = X509_get_subject_name(crt);
    } else {
        name = X509_get_issuer_name(crt);
    }
    if (name == NULL) {
        return -1;
    }
    //int cn_id = NID_commonName;
    //X509_NAME_get_text_by_NID(name, NID_commonName, cn, buff_size);

    loc = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
    if (loc < 0) {
        return -1;
    }
    ent = X509_NAME_get_entry(name, loc);
    if (ent == NULL) {
        return -1;
    }
    if (ent->value == NULL || ent->value->data == NULL) {
        return -1;
    }
    nbytes = (ent->value->length > buff_size) ? buff_size : ent->value->length;
    data = ent->value->data;
    for (i = 0; i < nbytes; i++) {
        *cn_ptr++ = *data++;
    }
    *cn_ptr++ = '\0';
    return 0;
}

int decodeX509(char **x509str, X509 *crt) {
    char *str_out;
    char cn[CNSTRSIZE + 1];

    X509_NAME *issuer;
    X509_NAME *subject;
    int str_size = 0;
    int i = 0;
    BIO *b = BIO_new(BIO_s_mem());
    if (crt == NULL) {
        *x509str = (char *) malloc(sizeof (char));
        x509str[0] = '\0';
        printf("x509 was null\n");
        return -1;
    }

    BIO_printf(b, "#X509 Certificate:\n");

    BIO_printf(b, "#   issuer: ");
    issuer = X509_get_issuer_name(crt);
    if (issuer == NULL) {
        BIO_printf(b, "null");
    } else {
        X509_NAME_print_ex(b, issuer, 0, 0);
    }
    BIO_printf(b, "\n");

    decodeX509CN(cn, crt, 0, CNSTRSIZE);
    BIO_printf(b, "issuerCN=%s\n", cn);
    BIO_printf(b, "\n");

    BIO_printf(b, "#    subject: ");
    subject = X509_get_subject_name(crt);
    if (issuer == NULL) {
        BIO_printf(b, "null");
    } else {
        X509_NAME_print_ex(b, subject, 0, 0);
    }
    BIO_printf(b, "\n");
    decodeX509CN(cn, crt, 1, CNSTRSIZE);
    BIO_printf(b, "subjectCN=%s\n", cn);
    BIO_printf(b, "\n");

    BIO_printf(b, "PEM Encoding:\n");
    PEM_write_bio_X509(b, crt);
    BIO_printf(b, "\n");
    BIO_flush(b);
    str_size = BIO_ctrl_pending(b);
    str_out = (char *) malloc(sizeof (char) *(str_size + 1));
    if (str_out == NULL) {
        printf("Error allocating %i bytes for crt string\n", str_size);
        BIO_free(b);
        return -1;
    }
    BIO_read(b, str_out, str_size);
    str_out[str_size] = '\0';
    *x509str = str_out;
    BIO_free(b);
    return 1;
}

int free_string_list(string_list_t *sl) {
    int i;
    for (i - 0; i < sl->nwords; i++) {
        sl->string_list[i] = NULL;
    }
    if (sl->string_block != NULL) {
        free(sl->string_block);
        sl->string_block = NULL;
    }
    if (sl->string_list != NULL) {
        free(sl->string_list);
        sl->string_list = NULL;
    }
    sl->nwords = 0;
    return 0;
}

int chop(char *str_in) {
    int length = 0;
    length = strlen(str_in);
    if (length == 0) {
        return -1;
    }
    if (str_in[length - 1] != '\n') return 0;
    str_in[length - 1] = '\0';
    return 1;
}


// Split string on boundry and skip blanks

int split_string(string_list_t *sl, char *strin, char split_ch) {
    int nwords = 0;
    ;
    int nchars = 0;
    int i = 0;
    int nsize = 0;
    char *strPtr = NULL;
    char *curr_word = NULL;
    int nbytes = 0;
    if (strin == NULL) {
        return -1;
    }

    nsize = sizeof (char) *(strlen(strin) + 1);
    sl->string_block = (char *) malloc(nsize);
    if (sl->string_block == NULL) {
        return -1;
    }
    strcpy(sl->string_block, strin);
    strPtr = sl->string_block;
    for (;; strPtr++, nbytes++) {
        if (*strPtr == '\0') {
            if (nchars > 0) {
                nwords++;
            }
            break;
        }
        if (*strPtr == split_ch) {
            if (nchars <= 0) {
                continue; // Skip blanks
            }
            nwords++;
            nchars = 0;
        } else {
            nchars++;
        }
    }

    nsize = sizeof (char*) *(nwords + 1);
    sl->string_list = (char **) malloc(nsize);
    if (sl->string_list == NULL) {
        free(sl->string_block);
        return -1;
    }

    sl->nwords = nwords;
    for (i = 0; i <= nwords; i++) {
        sl->string_list[i] = NULL;
    }

    strPtr = sl->string_block;
    curr_word = strPtr;
    nchars = 0;
    nwords = 0;

    for (;; strPtr++) {
        if (*strPtr == '\0') {
            if (nchars > 0) {
                sl->string_list[nwords] = curr_word;
                nwords++;
            }
            break;
        }
        if (*strPtr == split_ch) {
            *strPtr = '\0';
            if (nchars <= 0) {
                // Skip this word since its 0 bytes long
                curr_word = strPtr + 1;
                continue;
            }
            sl->string_list[nwords] = curr_word;
            curr_word = strPtr + 1;
            nchars = 0;
            nwords++;
        } else {
            nchars++;
        }
    }
    return nwords;
}

int decodeX509Chain(char **x509str, STACK_OF(X509) * chain) {
    X509 *crt;
    BIO *b;
    char *str_out;
    char *x509_str;
    int i;
    int n_x509s;
    int str_size;
    b = BIO_new(BIO_s_mem());
    if (chain == NULL) {
        printf("Chain was empty\n");
        return -1;
    }
    n_x509s = sk_X509_num(chain);
    printf("X509 Chain\n");
    for (i = 0; i < n_x509s; i++) {
        crt = (X509 *) sk_X509_value(chain, i);
        if (decodeX509(&x509_str, crt) < 0) {
            BIO_printf(b, "chain was empty\n");
        } else {
            BIO_printf(b, "cert[%3i]:\n%s", i, x509_str);
            BIO_flush(b);
            free(x509_str);
        }
    }
    str_size = BIO_ctrl_pending(b);
    str_out = (char *) malloc(sizeof (char) *(str_size + 1));
    if (str_out == NULL) {
        printf("Error allocating %i bytes for out buffer\n", str_size + 1);
        return -1;
    }
    BIO_read(b, str_out, str_size);
    str_out[str_size] = '\0';
    *x509str = str_out;
    BIO_free(b);
    return 1;
}

int get_long_bits(char *bits_str, long bits) {
    int i;
    *bits_str++ = '0';
    for (i = CHAR_BIT * sizeof (long) - 2; i >= 0; i--) {
        *bits_str++ = bit_vals[(bits >> i)&1];
    }
    *bits_str++ = '\0';
}

int drain_bio(BIO *b, char **data) {
    char *str_out;
    int str_size;
    str_size = BIO_ctrl_pending(b);
    str_out = (char *) malloc(sizeof (char) *(str_size + 1));
    if (str_out == NULL) {
        *data = NULL;
        return -1;
    }
    str_out[str_size] = '\0';
    BIO_read(b, str_out, str_size);
    *data = str_out;
    return str_size;
}

int ssl_mode_str(char **buff, long m) {
    int resp = 0;
    char bits_str[sizeof (long) *CHAR_BIT + 1];
    get_long_bits(bits_str, m);
    BIO *b = BIO_new(BIO_s_mem());
    BIO_printf(b, "mode=%s {", bits_str);
    if (m & SSL_MODE_ENABLE_PARTIAL_WRITE) {
        BIO_printf(b, "|SSL_MODE_ENABLE_PARTIAL_WRITE ");
    }
    if (m & SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER) {
        BIO_printf(b, "|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER ");
    }
    if (m & SSL_MODE_AUTO_RETRY) {
        BIO_printf(b, "|SSL_MODE_AUTO_RETRY ");
    }
#if defined SSL_MODE_RELEASE_BUFFERS
    if (m & SSL_MODE_RELEASE_BUFFERS) {
        BIO_printf(b, "|SSL_MODE_RELEASE_BUFFERS ");
    }
#endif
    BIO_printf(b, "}");
    resp = drain_bio(b, buff);
    BIO_free(b);


}

int init_ssl_lib() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

double gettimevalue() {
    double out;
    struct timeval tv;
    if (gettimeofday(&tv, NULL) == -1) {
        perror("Error in call to xgettimeofday(&tv)\n");
        return (-1.0);
    }
    out = (double) tv.tv_sec + (double) tv.tv_usec * 0.000001;
    return (out);
}
