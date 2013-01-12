#include <netdb.h>
#include <stdio.h>
#include <unbound.h>
#ifndef S_SPLINT_S
#include <ldns/ldns.h>
#endif  /* S_SPLING_S */
#include "unbify.h"
#include "dlfunc.h"

#define UNBIFY_GHBN_BUFSZ   1024

typedef struct hostent *(*ghbn_signature)(const char*);

/*@-incondefs@*/
/*@null@*/
struct hostent *gethostbyname(const char *name) {
/*@=incondefs@*/
    ghbn_signature _gethostbyname = NULL;
    static struct hostent h;
    static char buf[UNBIFY_GHBN_BUFSZ];
    int i, n;
    size_t len, off = 0;
    struct ub_result * r;

    if (!_gethostbyname)
        _gethostbyname = (ghbn_signature)dlfunc(RTLD_NEXT, "gethostbyname");

    if ( !(r = unbify_resolve(name)) )
        return _gethostbyname(name);

    h_errno = 0;
    if ( r->rcode != LDNS_RCODE_NOERROR ) {
        if ( r->rcode == LDNS_RCODE_SERVFAIL )
            h_errno = TRY_AGAIN;
        else if ( r->rcode == LDNS_RCODE_NXDOMAIN )
            h_errno = HOST_NOT_FOUND;
        else
            h_errno = NO_RECOVERY;
    }
    if ( h_errno == 0 && r->havedata == 0 )
        h_errno = NO_DATA;
    if ( h_errno != 0 ) {
        ub_resolve_free(r);
        /*@-mustfreefresh@*/
        return NULL;
        /*@=mustfreefresh@*/
    }

    // h_name
    len = strlen(r->qname);
    if ( off + len + 1 > UNBIFY_GHBN_BUFSZ ) {
        ub_resolve_free(r);
        /*@-mustfreefresh@*/
        return NULL;
        /*@=mustfreefresh@*/
    }
    /*@-mustfreeonly -statictrans@*/
    h.h_name = buf;
    /*@=mustfreeonly =statictrans@*/
    strcpy(h.h_name, r->qname);
    off += len + 1;

    // h_aliases
    if ( off + sizeof(char*) > UNBIFY_GHBN_BUFSZ ) {
        ub_resolve_free(r);
        /*@-mustfreefresh@*/
        return NULL;
        /*@=mustfreefresh@*/
    }
    /*@-mustfreeonly@*/
    h.h_aliases = (char**)(buf + off);
    /*@=mustfreeonly@*/
    h.h_aliases[0] = NULL;
    off += sizeof(char*);

    // h_addrtype, h_length - gethostbyname() is for ipv4 only
    h.h_addrtype = AF_INET;
    h.h_length = 4;

    len = 0;
    for ( n = 0; r->data[n] != NULL; n++ )
        len += r->len[n];

    if ( off + len + sizeof(char*) * (n + 1) > UNBIFY_GHBN_BUFSZ ) {
         ub_resolve_free(r);
        /*@-mustfreefresh@*/
        return NULL;
        /*@=mustfreefresh@*/
    }

    /*@-mustfreeonly@*/
    h.h_addr_list = (char**)(buf + off + len);
    /*@=mustfreeonly@*/
    for ( i = 0; i < n ; i ++ ) {
        h.h_addr_list[i] =  memcpy(buf + off, r->data[i], (size_t)r->len[i]);
        off += r->len[i];
    }
    h.h_addr_list[i + 1] = NULL;

    ub_resolve_free(r);
    /*@-mustfreefresh -compmempass -immediatetrans -nullret@*/
    return &h;
    /*@=mustfreefresh =compmempass =immediatetrans =nullret@*/
}
