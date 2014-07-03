#include<stdio.h>
#include<openssl/objects.h>
#include "sockutils.h"

int usage(char *prog) {
    printf("usage is %s <nid>\n", prog);
    printf("\n");
    printf("print the shortname for the nid\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 0;
    }
    char *sn;
    char *ln;
    int nid = atoi(argv[1]);
    printf("searching for nid shortname for %i\n", nid);
    sn = (char *) OBJ_nid2sn(nid);
    ln = (char *) OBJ_nid2ln(nid);
    printf("sb=\"%s\" ln=\"%s\"\n", sn, ln);
    return 0;
}
