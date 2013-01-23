#ifndef _UNBIFY_H_
#define	_UNBIFY_H_

/*@null@*/ struct ub_result * unbify_resolve(const char * hostname);
bool is_ipv4_addr(const char * hostname);

#endif	/* _UNBIFY_H_ */