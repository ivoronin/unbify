#include <stdio.h>
#include <unbound.h>
#ifndef S_SPLINT_S
#include <ldns/ldns.h>
#endif  /* S_SPLINT_S */
#include <assert.h>
#include "unbify.h"

void unbify_log_error(const char * errstr) {
    (void)fprintf(stderr, "%s: %s\n", "unbify", errstr);
}

struct ub_result * unbify_resolve(const char *hostname) {
    /*@only@*/ static struct ub_ctx * u = NULL;
    struct ub_result * r = NULL;
    int ub_err;

    assert(hostname != NULL);

    if ( u == NULL ) {
        if ( (u = ub_ctx_create()) == NULL ) {
            unbify_log_error("ub_ctx_create() error");
            return NULL;
        }

        if ( (ub_err = ub_ctx_config(u, UNBOUND_CONFIG_FILE)) != 0 ) {
            /*@-mustfreefresh@*/
            unbify_log_error(ub_strerror(ub_err));
            /*@=mustfreefresh@*/
            ub_ctx_delete(u);
            u = NULL;
            return NULL;
        }
    }

    /*@-unrecog@*/
    if ( (ub_err = ub_resolve(u, (char*)hostname, LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, &r)) != 0 ) {
        /*@=unrecog -mustfreefresh@*/
        unbify_log_error(ub_strerror(ub_err));
        /*@=mustfreefresh@*/
        if (r) {
            ub_resolve_free(r);
            return NULL;
        }
    }

    return r;
}