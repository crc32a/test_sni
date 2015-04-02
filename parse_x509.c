#include<stdio.h>
#include<openssl/asn1.h>
#include<openssl/x509.h>
#include<openssl/x509v3.h>
#include<openssl/objects.h>
#include<openssl/pem.h>
#include<openssl/safestack.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<unistd.h>
#include<fcntl.h>
#include<string.h>

#include"sockutils.h"

#define MYPATH_MAX 512
#define STRSIZE 128

const char * const boolStr[] = {"false", "true"};

typedef struct {
    char *short_name;
    char *long_name;
    char *oid;
    ASN1_STRING value;
    int nid;
} X509_NAME_component_t;

typedef struct {
    X509_NAME_component_t *entries;
    int n_entries;
} X509_NAME_components_t;

int usage(char *prog) {
    printf("usage %s <x509_pem>\n", prog);
    printf("\n");
    printf("    parse up the interesting features of an X509 file\n");
    return 0;
}

int X509_NAME_components_new(X509_NAME_components_t **comps, int n_entries) {
    int tmp_size = 0;
    int i = 0;
    X509_NAME_components_t *comps_st = NULL;
    X509_NAME_component_t *entries_st = NULL;
    tmp_size = sizeof (X509_NAME_components_t);
    comps_st = (X509_NAME_components_t *) malloc(tmp_size);
    if (comps_st == NULL) {
        return -1;
    }
    tmp_size = sizeof (X509_NAME_component_t) * n_entries;
    entries_st = (X509_NAME_component_t *) malloc(tmp_size);
    if (entries_st == NULL) {
        free(comps_st);
        return -2;
    }
    comps_st->n_entries = n_entries;
    comps_st->entries = entries_st;
    for (i = 0; i < n_entries; i++) {
        comps_st->entries[i].nid = 0;
        comps_st->entries[i].long_name = NULL;
        comps_st->entries[i].short_name = NULL;
        comps_st->entries[i].oid = NULL;
        comps_st->entries[i].value.data = NULL;
        comps_st->entries[i].value.flags = 0;
        comps_st->entries[i].value.length = 0;
        comps_st->entries[i].value.type = 0;
    }
    *comps = comps_st;
    return 0;
}

int X509_NAME_components_free(X509_NAME_components_t *st) {
    int n_entries = 0;
    int i = 0;
    n_entries = st->n_entries;
    for (i = 0; i < n_entries; i++) {
        if (st->entries[i].long_name != NULL) {
            free(st->entries[i].long_name);
            st->entries[i].long_name = NULL;
        }
        if (st->entries[i].short_name != NULL) {
            free(st->entries[i].short_name);
            st->entries[i].short_name = NULL;
        }
        if (st->entries[i].value.data != NULL) {
            free(st->entries[i].value.data);
            st->entries[i].value.data = NULL;
        }
        if (st->entries[i].oid != NULL) {
            free(st->entries[i].oid);
            st->entries[i].oid = NULL;
        }
    }
    st->n_entries = 0;
    free(st->entries);
    st->entries = NULL;
    free(st);

    return 0;
}

int decodeX509NameComponents(X509_NAME *name, X509_NAME_components_t **comps) {
    char buff[STRSIZE + 1];
    int tmp_size = 0;
    int n_entries = 0;
    int i = 0;
    int j;
    int nid = 0;
    int str_len = 0;
    char *sn = NULL;
    char *ln = NULL;
    const ASN1_OBJECT *obj = NULL;
    X509_NAME_ENTRY *ne = NULL;
    n_entries = sk_X509_NAME_ENTRY_num(name->entries);
    X509_NAME_components_t *comps_st;
    if (X509_NAME_components_new(&comps_st, n_entries) < 0) {
        return -1;
    }

    for (i = 0; i < n_entries; i++) {
        ne = sk_X509_NAME_ENTRY_value(name->entries, i);
        nid = OBJ_obj2nid(ne->object);
        comps_st->entries[i].nid = nid;
        sn = (char *) OBJ_nid2sn(nid);
        ln = (char *) OBJ_nid2ln(nid);
        str_len = strlen(sn);
        comps_st->entries[i].short_name = (char *) malloc(str_len + 1);
        comps_st->entries[i].nid = nid;
        if (comps_st->entries[i].short_name != NULL) {
            strncpy(comps_st->entries[i].short_name, sn, str_len);
            comps_st->entries[i].short_name[str_len] = '\0';
        }

        str_len = strlen(ln);
        comps_st->entries[i].long_name = (char *) malloc(str_len + 1);
        if (comps_st->entries[i].long_name != NULL) {
            strncpy(comps_st->entries[i].long_name, ln, str_len);
            comps_st->entries[i].long_name[str_len] = '\0';
        }
        comps_st->entries[i].value.flags = ne->value->flags;
        comps_st->entries[i].value.length = ne->value->length;
        comps_st->entries[i].value.type = ne->value->type;
        str_len = ne->value->length;
        comps_st->entries[i].value.data = (unsigned char *) malloc(str_len + 1);
        if (comps_st->entries[i].value.data != NULL) {
            memcpy(comps_st->entries[i].value.data, ne->value->data, str_len);
            comps_st->entries[i].value.data[str_len] = '\0';
        }
        obj = (const ASN1_OBJECT *) ne->object;
        str_len = OBJ_obj2txt(buff, STRSIZE, obj, 1);
        if (str_len > 0) {
            comps_st->entries[i].oid = (char *) malloc(str_len + 1);
            if (comps_st != NULL) {
                strncpy(comps_st->entries[i].oid, buff, str_len);
                comps_st->entries[i].oid[str_len] = '\0';
            }
        }
    }
    *comps = comps_st;
    return n_entries;
}

int get_subject(char **subject, X509 * x509) {
    X509_NAME_components_t *comps = NULL;
    X509_NAME *name = NULL;
    int n_comps = 0;
    name = X509_get_subject_name(x509);
    if (decodeX509NameComponents(name, &comps) < 0) {
        return -1;
    }
    if (x509comps_string(subject, comps) < 0) {
        return -1;
    }
    X509_NAME_components_free(comps);
    return 0;
}

int get_issuer(char **issuer, X509 * x509) {
    X509_NAME_components_t *comps = NULL;
    X509_NAME *name = NULL;
    int n_comps = 0;
    name = X509_get_issuer_name(x509);
    if (decodeX509NameComponents(name, &comps) < 0) {
        return -1;
    }
    if (x509comps_string(issuer, comps) < 0) {
        return -1;
    }
    X509_NAME_components_free(comps);
    return 0;
}

int x509comps_string(char **str, X509_NAME_components_t *comps) {
    BIO *b = NULL;
    int i = 0;
    int n_entries = 0;
    b = BIO_new(BIO_s_mem());
    if (b == NULL) {
        return -1;
    }
    n_entries = comps->n_entries;
    if (n_entries <= 0) {
        BIO_flush(b);
        drain_bio(b, str);
        BIO_free(b);
        return 0;
    }
    BIO_printf(b, "%s", "[\n");
    for (i = 0; i < n_entries; i++) {
        BIO_printf(b, "(nid=%i, ", comps->entries[i].nid);
        BIO_printf(b, "oid=%s, ", comps->entries[i].oid);
        BIO_printf(b, "short_name=\"%s\", ", comps->entries[i].short_name);
        BIO_printf(b, "ln=\"%s\", ", comps->entries[i].long_name);
        BIO_printf(b, "val=\"%s\")\n", comps->entries[i].value.data);
    }
    BIO_printf(b, "%s", "]\n");
    BIO_flush(b);
    drain_bio(b, str);
    BIO_free(b);
    return 0;
}

int get_general_name_string(char **type, char **val, GENERAL_NAME *gn) {
    BIO *type_bio = NULL;
    BIO *val_bio = NULL;
    unsigned char *p = NULL;
    int n_comps = 0;
    X509_NAME *name = NULL;
    X509_NAME_components_t *comps = NULL;
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
                break;
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
                x509comps_string(&comp_str, comps);
                BIO_printf(val_bio, "%s", comp_str);
                X509_NAME_components_free(comps);
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
            free(type);
            type = NULL;
            free(val);
            val = NULL;
        }
    }
    BIO_flush(b);
    if (gens != NULL) {
        GENERAL_NAMES_free(gens);
    }
    if (drain_bio(b, vals) < 0) {
        BIO_free(b);
        return -1;
    };
    BIO_free(b);
    return 0;
}

int main(int argc, char **argv) {
    char *fmt = NULL;
    char *subject = NULL;
    char *issuer = NULL;
    char *line = NULL;
    char *file_name = NULL;
    char *obj_name = NULL;
    char *oid_str = NULL;
    unsigned char *dataPtr = NULL;
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
    int j = 0;
    int n_exts = 0;
    int n_loops; // testing for memory leaks.
    int nid = 0;
    pid_t this_pid = 0;
    double start_time = 0.0;
    double end_time = 0.0;
    double delta_time = 0.0;
    this_pid = getpid();
    tmp_size = sizeof (char) *(STRSIZE + 1);
    line = (char *) malloc(tmp_size);
    if (line == NULL) {
        printf("Error allocating %i bytes for line buffer\n", tmp_size);
        return -1;
    }
    file_name = (char *) malloc(tmp_size);
    if (file_name == NULL) {
        printf("Error allocating %i bytes for file_name\n", tmp_size);
    }
    oid_str = (char *) malloc(tmp_size);
    if (oid_str == NULL) {
        printf("Error allocating %i bytes for oid buffer\n", tmp_size);
    }
    tmp_size = sizeof (X509V3_CTX);
    ctx = (X509V3_CTX *) malloc(tmp_size);
    if (ctx == NULL) {
        fmt = "Error failed to allocate %i bytes for X509 CTX object\n";
        printf(fmt, tmp_size);
        return -1;
    }
    if (argc >= 2) {
        strncpy(file_name, argv[1], STRSIZE);
    } else {
        printf("Enter x509 file name: ");
        fflush(stdout);
        if (fgets(file_name, STRSIZE, stdin) == NULL) {
            printf("Error reading file name from stdin\n");
            return -1;
        }
    }


    chop(file_name);
    init_ssl_lib();
    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (out == NULL) {
        printf("Error creating output BIO file\n");
        return -1;
    }
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
    printf("x509 contains %i extensions\n", n_exts);
    // Leak loop
    for (;;) {
        fmt = "pid[%i]: Enter number of times to decode file %s: ";
        printf(fmt, this_pid, file_name);
        if (fgets(line, STRSIZE, stdin) == NULL) {
            printf("unable to read from stdin. Possible EOF\n");
            break;
        }
        chop(line);
        n_loops = atoi(line);
        printf("Decoding %i times\n", n_loops);
        start_time = gettimevalue();
        for (j = 0; j <= n_loops; j++) {
            if (get_subject(&subject, x509) >= 0) {
                if (j == n_loops) printf("subjectName\n%s\n", subject);
                free(subject);
            }
            if (get_issuer(&issuer, x509) >= 0) {
                if (j == n_loops) printf("issuerName\n%s\n", issuer);
                free(issuer);
            }
            if (j == n_loops) printf("Found %i extensions\n", n_exts);
            for (i = 0; i < n_exts; i++) {
                ext = X509_get_ext(x509, i);
                if (ext == NULL) {
                    printf("Error getting X509 extension\n");
                    return -1;
                }
                nid = OBJ_obj2nid(ext->object);
                obj_name = (char *) OBJ_nid2sn(nid);
                if (j == n_loops) {
                    fmt = "ext[%i]: nid=%i = \"%s\" oid = %s critical=%s len = %i data=\"%s\"\n";
                    dataPtr = ext->value->data;
                    tmp_size = ext->value->length;
                    char_to_hex(&char_data, dataPtr, tmp_size);
                    OBJ_obj2txt(oid_str, STRSIZE, ext->object, 1);
                    BIO_printf(out, fmt, i, nid, obj_name, oid_str, boolStr[(ext->critical) & 0x1], tmp_size,char_data);
//                    free(char_data);
                }
                if (nid == NID_subject_alt_name) {
                    getNamesFromAltSubjectNameExt(&gn_str, ext);
                    if (j == n_loops) {
                        BIO_printf(out, "Decoded GeneralName = %s\n", gn_str);
                    }
                    free(gn_str);
                    BIO_flush(out);
                }
                if (j == n_loops) X509V3_EXT_print(out, ext, 0, 0);
                if (j == n_loops) BIO_printf(out, "\n");
            }
        }
        end_time = gettimevalue();
        delta_time = end_time - start_time;
        printf("Took %f seconds to iterate %i times\n", delta_time, n_loops);
    }
    free(line);
    free(file_name);
    BIO_free(out);
    return 0;
}
