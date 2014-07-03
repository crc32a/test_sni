#include<stdio.h>
#include<openssl/asn1.h>
#include<openssl/x509.h>
#include<openssl/x509v3.h>
#include<openssl/pem.h>
#include<openssl/safestack.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<unistd.h>
#include<fcntl.h>
#include<string.h>

#include"sockutils.h"

#define MYPATH_MAX 512
#define STRSIZE 1024

struct X509_NAME_component {
    char *short_name;
    char *val;
    int nid;
};

int usage(char *prog) {
    printf("usage %s <x509_pem>\n", prog);
    printf("\n");
    printf("    parse up the interesting features of an X509 file\n");
    return 0;
}

int decodeX509NameComponents(X509_NAME *name, struct X509_NAME_component **comps) {
    int tmp_size = 0;
    BIO *b = NULL;
    int n_entries = 0;
    int i = 0;
    int nid = 0;
    char *sn = NULL;
    struct X509_NAME_component *c = NULL;
    X509_NAME_ENTRY *ne = NULL;
    b = BIO_new(BIO_s_mem());
    if (b == NULL) {
        return -1;
    }
    n_entries = sk_X509_NAME_ENTRY_num(name->entries);
    tmp_size = sizeof (struct X509_NAME_component) *n_entries;
    c = (struct X509_NAME_component *) malloc(tmp_size);
    for (i = 0; i < n_entries; i++) {
        ne = sk_X509_NAME_ENTRY_value(name->entries, i);
        nid = OBJ_obj2nid(ne->object);
        c[i].nid = nid;
        sn = (char *) OBJ_nid2sn(nid);
        c[i].short_name = sn;
    }
    BIO_free(b);
    *comps = c;
    return n_entries;
}

int x509comps_string(char **str, struct X509_NAME_component *comps, int n_comps) {
    BIO *b;
    int i;
    b = BIO_new(BIO_s_mem());
    if (b == NULL) {
        return -1;
    }
    if (n_comps <= 0) {
        BIO_flush(b);
        drain_bio(b, str);
        BIO_free(b);
        return 0;
    }
    BIO_printf(b, "%s", "[");
    for (i = 0; i < n_comps; i++) {
        BIO_printf(b, "(\"%i\",\"%s\",\"%p\")", comps[i].nid, comps[i].short_name, comps[i].val);
    }
    BIO_printf(b, "%s", "]");
    BIO_flush(b);
    drain_bio(b, str);
    return 0;
}

int get_general_name_string(char **type, char **val, GENERAL_NAME *gn) {
    BIO *type_bio = NULL;
    BIO *val_bio = NULL;
    unsigned char *p = NULL;
    int n_comps = 0;
    X509_NAME *name = NULL;
    struct X509_NAME_component *comps = NULL;
    char *comp_str = NULL;
    int status = 0;
    int i = 0;
    type_bio = BIO_new(BIO_s_mem());
    if (type_bio == NULL) {
        return -1;
    }
    val_bio = BIO_new(BIO_s_mem());
    if (val_bio == NULL) {
        BIO_free(type_bio);
        status = -1;
        return status;
    }

    switch (gn->type) {
        case GEN_OTHERNAME:
            BIO_printf(type_bio, "%s", "othername");
            BIO_printf(val_bio, "%s", "<unsupported>");
            break;
        case GEN_X400:
            BIO_printf(type_bio, "%s", "X400Name");
            BIO_printf(val_bio, "%s", "<unsupported>");
            break;
        case GEN_EDIPARTY:
            BIO_printf(type_bio, "%s", "EdiPartyName");
            BIO_printf(val_bio, "%s", "<unsupported>");
            break;
        case GEN_EMAIL:
            BIO_printf(type_bio, "%s", "email");
            BIO_printf(val_bio, "%s", gn->d.ia5->data);
            break;
        case GEN_DNS:
            BIO_printf(type_bio, "%s", "DNS");
            BIO_printf(val_bio, "%s", gn->d.ia5->data);
            break;
        case GEN_URI:
            BIO_printf(type_bio, "%s", "URI");
            BIO_printf(val_bio, "%s", gn->d.ia5->data);
            break;
        case GEN_IPADD:
            BIO_printf(type_bio, "%s", "IP");
            p = gn->d.ip->data;
            if (gn->d.ip->length == 4) {
                BIO_printf(val_bio, "%i.%i.%i.%i", p[0], p[1], p[2], p[3]);
                return 0;
            } else if (gn->d.ip->length == 16) {
                for (i = 0; i < 7; i++) {
                    BIO_printf(val_bio, "%X:", (p[0] << 4) | p[1]);
                    p += 2;
                }
                BIO_printf(val_bio, "%X", (p[0] << 4) | p[1]);
            }
            break;
        case GEN_RID:
            BIO_printf(type_bio, "RID");
            i2a_ASN1_OBJECT(val_bio, gn->d.rid);
            break;
        case GEN_DIRNAME:
            BIO_printf(type_bio, "DirName");
            name = gn->d.directoryName;
            n_comps = decodeX509NameComponents(name, &comps);
            if (n_comps > 0) {
                x509comps_string(&comp_str, comps, n_comps);
                BIO_printf(val_bio, "%s", comp_str);
                free(comps);
                free(comp_str);
            }
            break;
        default:
            BIO_printf(type_bio, "%s", "UNKNOWN");
            BIO_printf(val_bio, "%s", "UNKNOWN");
            break;
    }
    BIO_flush(type_bio);
    BIO_flush(val_bio);
    if (drain_bio(type_bio, type) < 0) {
        status = -1;
        *type = NULL;
    } else if (drain_bio(val_bio, val) < 0) {
        free(type);
        *type = NULL;
        *val = NULL;
        status = -1;
    };
    BIO_free(type_bio);
    BIO_free(val_bio);
    return status;
}

int getNamesFromAltSubjectNameExt(char **vals, X509_EXTENSION *ext) {
    BIO *b = NULL;
    char *type = NULL;
    char *val = NULL;
    X509 *cert = NULL;
    STACK_OF(GENERAL_NAME) *gens = NULL;
    GENERAL_NAME *gn = NULL;
    int num = 0;
    int len = 0;
    int i = 0;
    int status = 0;
    b = BIO_new(BIO_s_mem());
    gens = X509V3_EXT_d2i(ext);
    num = sk_GENERAL_NAME_num(gens);

    for (i = 0; i < num; ++i) {
        gn = sk_GENERAL_NAME_value(gens, i);
        status = get_general_name_string(&type, &val, gn);
        if (status == 0) {
            BIO_printf(b, "%s:%s\n", type, val);
        }
    }
    BIO_flush(b);
    if (drain_bio(b, vals) < 0) {
        BIO_free(b);
        return -1;
    };
    BIO_free(b);
    return 0;
}

int getSubject(char **subject, X509 * x509) {

    return 0;
}

int main(int argc, char **argv) {
    char *file_name = NULL;
    char *obj_name = NULL;
    int tmp_size = 0;
    char *char_data = NULL;
    X509V3_CTX *ctx = NULL;
    X509 *x509 = NULL;
    FILE *fp = NULL;
    BIO *out = NULL;
    char *gn_str = NULL;
    X509_EXTENSION *ext = NULL;
    ASN1_OCTET_STRING *data = NULL;
    int i = 0;
    int n_exts = 0;
    int nid = 0;
    if (argc < 2) {
        usage(argv[0]);
        return 0;
    }
    tmp_size = sizeof (char) *(STRSIZE + 1);
    file_name = (char *) malloc(tmp_size);
    if (file_name == NULL) {
        printf("Error allocating %i bytes for file_name\n", tmp_size);
    }
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
    strncpy(file_name, argv[1], STRSIZE);
    fp = fopen(file_name, "r");
    if (fp == NULL) {
        printf("Error opening file %s\n", file_name);
        return -1;
    }
    if (PEM_read_X509(fp, &x509, NULL, NULL) == NULL) {
        printf("Error reading x509 file\n");
        return -1;
    }
    if (fclose(fp) != 0) {
        perror("Odd coulden't close x509 file:");
    }
    n_exts = X509_get_ext_count(x509);
    printf("Found %i extensions\n", n_exts);
    for (i = 0; i < n_exts; i++) {
        //ext = X509_EXTENSION_new();
        ext = X509_get_ext(x509, i);
        if (ext == NULL) {
            printf("Error getting X509 extension\n");
            return -1;
        }
        nid = OBJ_obj2nid(ext->object);
        obj_name = (char *) OBJ_nid2sn(nid);
        BIO_printf(out, "ext[%i]: nid=%i = \"%s\"\n", i, nid, obj_name);
        if (nid == NID_subject_alt_name) {
            getNamesFromAltSubjectNameExt(&gn_str, ext);
            BIO_printf(out, "Decoded GeneralName = %s\n", gn_str);
            BIO_flush(out);
        }
        X509V3_EXT_print(out, ext, 0, 0);
        BIO_printf(out, "\n");
        X509_EXTENSION_free(ext);
    }
    free(file_name);
    BIO_free(out);
    return 0;
}
