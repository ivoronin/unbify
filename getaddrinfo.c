#include <netdb.h>
#include <arpa/inet.h>
#ifndef S_SPLINT_S
#include <ldns/ldns.h>
#endif /* S_SPLINT_S */
#include <unbound.h>
#include "dlfunc.h"
#include "unbify.h"
#include "debug.h"

typedef int (*gai_signature)(const char*, const char*, const struct addrinfo*, struct addrinfo**);

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    gai_signature _getaddrinfo = NULL;
    struct ub_result *r;
    struct addrinfo *ai = NULL, *ai_prev = NULL;
    char *dlerrstr;
    int gai_errno = 0, i;

    if (!_getaddrinfo) {
        (void)dlerror();
        _getaddrinfo = (gai_signature)dlfunc(RTLD_NEXT, "getaddrinfo");
        dlerrstr = dlerror();
        if ( dlerrstr ) {
            unbify_log_error(dlerrstr);
            exit(EXIT_FAILURE);
        }
    }

    /* Fallback */
    if ( !node || (hints &&
        (hints->ai_family == AF_INET6 ||                    /* IPv6 */
        hints->ai_flags & AI_NUMERICHOST ||                 /* Don't use name resolution. */
        hints->ai_flags & AI_IDN ||                         /* IDN */
        hints->ai_flags & AI_IDN_ALLOW_UNASSIGNED ||        /* IDN */
        hints->ai_flags & AI_IDN_USE_STD3_ASCII_RULES )))   /* IDN */
        return _getaddrinfo(node, service, hints, res);

    /* Fallback: libunbound error */
    if ( !(r = unbify_resolve(node)) )
        return _getaddrinfo(node, service, hints, res);

    /*@-unrecog@*/
    if ( r->rcode != LDNS_RCODE_NOERROR ) {
        if ( r->rcode == LDNS_RCODE_SERVFAIL )
            gai_errno = EAI_AGAIN;
        else if ( r->rcode == LDNS_RCODE_NXDOMAIN )
        /*@=unrecog@*/
            gai_errno = EAI_ADDRFAMILY;
        else
            gai_errno = EAI_FAIL;
    }
    if ( r->havedata == 0 )
        gai_errno = EAI_NODATA;

    if ( gai_errno != 0 ) {
        ub_resolve_free(r);
        /*@-mustfreefresh@*/
        return(gai_errno);
        /*@=mustfreefresh@*/
    }

    for ( i = 0; r->data[i] != NULL; i++ ) {
        if ( (gai_errno = _getaddrinfo(inet_ntoa(*(struct in_addr*)(r->data[i])),
            service, hints, &ai)) != 0 ) {
            ub_resolve_free(r);
            /*@-mustfreefresh@*/
            return gai_errno;
            /*@=mustfreefresh@*/
        }

        if ( ai_prev == NULL )
            *res = ai_prev = ai;
        else {
            assert(ai_prev->ai_next == NULL);
            ai_prev->ai_next = ai;
            ai_prev = ai_prev->ai_next;
        }
    }

    ub_resolve_free(r);

    /*@-mustfreefresh -nullstate@*/
    return 0;
    /*@=mustfreefresh =nullstate@*/
}