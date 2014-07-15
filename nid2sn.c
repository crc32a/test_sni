#include<stdio.h>
#include<openssl/objects.h>
#include<string.h>
#include "sockutils.h"

#define STRSIZE 512

int usage(char *prog) {
    printf("usage is %s <nid>\n", prog);
    printf("\n");
    printf("print the shortname for the nid\n");
    return 0;
}

int main(int argc, char **argv) {
    ASN1_OBJECT *obj = NULL;
    int tmp_size = 0;
    int oid_len = 0;
    if (argc < 2) {
        usage(argv[0]);
        return 0;
    }
    char *oid = NULL;
    char *sn = NULL;
    char *ln = NULL;
    oid = (char *) malloc(STRSIZE + 1);
    if (oid == NULL) {
        printf("Error allocating %i bytes for oid string\n", STRSIZE + 1);
    }
    oid[STRSIZE] = '\0';
    int nid = atoi(argv[1]);
    printf("searching for nid shortname for %i\n", nid);
    sn = (char *) OBJ_nid2sn(nid);
    ln = (char *) OBJ_nid2ln(nid);
    obj = OBJ_nid2obj(nid);
    if (obj != NULL) {
        oid_len = OBJ_obj2txt(oid, STRSIZE, obj, 1);
        if (oid_len > 0) {
            oid[oid_len] = '\0';
        } else {
            strncpy(oid, "Unkown", STRSIZE);
        }
    } else {
        oid = strncpy(oid, "Unknown", STRSIZE);
    }
    printf("sb=\"%s\" ln=\"%s\" oid=\"%s\"\n", sn, ln, oid);
    free(oid);
    return 0;
}
