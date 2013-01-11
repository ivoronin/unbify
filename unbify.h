#ifndef _UNBIFY_H_
#define	_UNBIFY_H_

/*@null@*/ struct ub_result * unbify_resolve(const char * hostname);
void unbify_log_error(const char * errstr);

#endif	/* _UNBIFY_H_ */