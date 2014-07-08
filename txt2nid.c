#include<stdio.h>
#include<openssl/ssl.h>

#include"sockutils.h"

int usage(char *prog) {
    printf("usage is %s <nidStr>\n", prog);
    printf("\n");
    printf("Lookup the nid ID by the string name\n");
    return 0;
}

int main(int argc, char **argv) {
    char *nid_str;
    int nid_id;
    if (argc < 2) {
        usage(argv[0]);
        return 0;
    }
    nid_str = argv[1];
    printf("OBJ_txt2nid(\"%s\")=%i\n", nid_str, OBJ_txt2nid(nid_str));
    printf("OBJ_sn2nid(\"%s\")=%i\n", nid_str, OBJ_sn2nid(nid_str));
    printf("OBJ_ln2nid(\"%s\")=%i\n", nid_str, OBJ_ln2nid(nid_str));
    return 0;
}
