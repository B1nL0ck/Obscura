#ifndef MODULE_API_H
#define MODULE_API_H

#include <stddef.h>

const char *module_name(void);
int module_init(void);
void module_free(void);
int module_process(const unsigned char *in, size_t inlen,
                   unsigned char **out, size_t *outlen);

#endif
