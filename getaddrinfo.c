#include <netdb.h>
#include <arpa/inet.h>
#ifndef S_SPLINT_S
#include <ldns/ldns.h>
#endif /* S_SPLINT_S */
#include <unbound.h>
#include "dlfunc.h"
#include "unbify.h"

typedef int (*gai_signature)(const char*, const char*, const struct addrinfo*, struct addrinfo**);

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    gai_signature _getaddrinfo = NULL;
    struct ub_result *r;
    /*@-compdestroy@*/
    struct addrinfo *ai = NULL, *ai_prev = NULL, hintsn = {
        .ai_flags = AI_V4MAPPED | AI_ADDRCONFIG,
        .ai_family = PF_UNSPEC,
        .ai_socktype = 0,
        .ai_protocol = 0,
        .ai_addrlen = 0,
        .ai_addr = NULL,
        .ai_canonname = NULL,
        .ai_next = NULL
    };
    char *addr;
    int gai_errno = 0, i;
    size_t l;

    if (!_getaddrinfo) {
        _getaddrinfo = (gai_signature)dlfunc(RTLD_NEXT, "getaddrinfo");
        assert(_getaddrinfo != NULL);
    }

    /* Fallback */
    if ( !node || (hints &&
        (hints->ai_family == AF_INET6 ||                    /* IPv6 */
        hints->ai_flags & AI_NUMERICHOST ||                 /* Don't use name resolution. */
        hints->ai_flags & AI_IDN ||                         /* IDN */
        hints->ai_flags & AI_IDN_ALLOW_UNASSIGNED ||        /* IDN */
        hints->ai_flags & AI_IDN_USE_STD3_ASCII_RULES )))   /* IDN */
        return _getaddrinfo(node, service, hints, res);

    if ( hints ) {
        hintsn.ai_family = hints->ai_family;
        hintsn.ai_socktype = hints->ai_socktype;
        hintsn.ai_protocol = hints->ai_protocol;
        hintsn.ai_flags = hints->ai_flags;
    }
    hintsn.ai_flags |=  AI_NUMERICHOST;

    /* IPv4 address */
    if ( is_ipv4_addr(node) )
	   return _getaddrinfo(node, service, &hintsn, res);

    /* Fallback: libunbound error */
    if ( !(r = unbify_resolve(node)) )
        return _getaddrinfo(node, service, hints, res);

    /*@-unrecog@*/
    if ( r->rcode != LDNS_RCODE_NOERROR ) {
        if ( r->rcode == LDNS_RCODE_SERVFAIL )
            gai_errno = EAI_AGAIN;
        else if ( r->rcode == LDNS_RCODE_NXDOMAIN )
        /*@=unrecog@*/
            gai_errno = EAI_NONAME;
        else
            gai_errno = EAI_FAIL;
    }
    if ( !gai_errno && r->havedata == 0 )
        gai_errno = EAI_NONAME;

    if ( gai_errno != 0 ) {
        ub_resolve_free(r);
        /*@-mustfreefresh@*/
        return(gai_errno);
        /*@=mustfreefresh@*/
    }

    for ( i = 0; r->data[i] != NULL; i++ ) {
        addr = inet_ntoa(*(struct in_addr*)(r->data[i]));
        if ( (gai_errno = _getaddrinfo(addr, service, &hintsn, &ai)) != 0 ) {
            ub_resolve_free(r);
            /*@-mustfreefresh@*/
            return gai_errno;
            /*@=mustfreefresh@*/
        }
        assert(ai != NULL);

        if ( ai_prev == NULL ) {
            *res = ai_prev = ai;
            if ( hints && hints->ai_flags & AI_CANONNAME ) {
                if ( r->canonname ) {
                    l = strlen(r->canonname);
                    /*@-unrecog@*/
                    ai->ai_canonname = strndup(r->canonname, r->canonname[l - 1] == '.' ? l - 1 : l);
                } else {
                    ai->ai_canonname = strdup(r->qname);
                    /*@=unrecog@*/
                }
            }
        } else {
            assert(ai_prev->ai_next == NULL);
            ai_prev = ai_prev->ai_next = ai;
        }
    }

    ub_resolve_free(r);

    /*@-mustfreefresh -nullstate@*/
    return 0;
    /*@=mustfreefresh =nullstate@*/
}