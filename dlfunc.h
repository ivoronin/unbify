#ifndef _DLFCN_H_
#define	_DLFCN_H_
#include <dlfcn.h>

struct __dlfunc_arg {
	int	__dlfunc_dummy;
};

typedef	void (*dlfunc_t)(struct __dlfunc_arg);
dlfunc_t dlfunc(void * __restrict, const char * __restrict);

#endif /* _DLFCN_H_ */