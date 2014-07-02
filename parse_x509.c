#include<stdio.h>
#include<openssl/x509.h>
#include<openssl/x509v3.h>
#include<openssl/pem.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<unistd.h>
#include<fcntl.h>
#include<string.h>

#include"sockutils.h"

#define MYPATH_MAX 512
#define STRSIZE 1024

int usage(char *prog) {
    printf("usage %s <x509_pem>\n", prog);
    printf("\n");
    printf("    parse up the interesting features of an X509 file\n");
    return 0;
}

int main(int argc, char **argv) {
    char file_name[STRSIZE + 1];
    char *obj_name;
    int tmp_size;
    X509V3_CTX *ctx = NULL;
    X509 *x509 = NULL;
    FILE *fp;
    BIO *out;
    X509_EXTENSION *ext;
    int i;
    int nExt;
    int subjectAltNameNID;
    int nid;
    tmp_size = sizeof (X509V3_CTX);
    ctx = (X509V3_CTX *) malloc(tmp_size);
    if (ctx == NULL) {
        printf("Error failed to allocate %i bytes for X509 CTX object\n", tmp_size);
        return -1;
    }
    init_ssl_lib();
    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (out == NULL) {
        printf("Error creating output BIO file\n");
        return -1;
    }
    subjectAltNameNID = OBJ_sn2nid("subjectAltName");
    strncpy(file_name, argv[1], STRSIZE);
    fp = fopen(file_name, "r");
    if (fp == NULL) {
        printf("Error opening file %s\n", file_name);
    }
    if (PEM_read_X509(fp, &x509, NULL, NULL) == NULL) {
        printf("Error reading x509 file\n");
        return -1;
    }
    if (fclose(fp) != 0) {
        perror("Odd coulden't close x509 file:");
    }
    nExt = X509_get_ext_count(x509);
    printf("Found %i extensions\n", nExt);
    for (i = 0; i < nExt; i++) {
        ext = X509_EXTENSION_new();
        if (ext == NULL) {
            printf("Error unable to allocate memory for extension\n");
            return -1;
        }
        ext = X509_get_ext(x509, i);
        if (ext == NULL) {
            printf("Error getting X509 extension\n");
            return -1;
        }
        nid = OBJ_obj2nid(ext->object);
        obj_name = (char *) OBJ_nid2sn(nid);
        BIO_printf(out, "ext[%i]: nid=%i = \"%s\": \"", i, nid, obj_name);
        X509V3_EXT_print(out, ext, 0, 0);
        BIO_printf(out, "\"\n");
        X509_EXTENSION_free(ext);
    }
    BIO_free(out);
    return 0;
}
