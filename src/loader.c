#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include "module_api.h"

typedef struct module_entry {
    char *name;
    void *handle;
    int (*init)(void);
    int (*process)(const unsigned char*, size_t, unsigned char**, size_t*);
    void (*cleanup)(void);
    struct module_entry *next;
} module_entry_t;

static module_entry_t *modules_head = NULL;
static module_entry_t *modules_tail = NULL;

static void add_module(module_entry_t *mod) {
    if (!modules_head) {
        modules_head = modules_tail = mod;
    } else {
        modules_tail->next = mod;
        modules_tail = mod;
    }
}

static int load_file_to_memory(const char *path, unsigned char **buf, size_t *len) {
    struct stat st;
    if (stat(path, &st) < 0) return -1;
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    *len = st.st_size;
    *buf = malloc(*len);
    if (!*buf) { fclose(fp); return -1; }
    if (fread(*buf, 1, *len, fp) != *len) { fclose(fp); free(*buf); return -1; }
    fclose(fp);
    return 0;
}

static void load_modules_from_dir(const char *dirpath) {
    DIR *dir = opendir(dirpath);
    if (!dir) { perror("opendir"); return; }
    struct dirent *d;
    while ((d = readdir(dir))) {
        if (strstr(d->d_name, ".so")) {
            char fullpath[512];
            snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, d->d_name);
            void *h = dlopen(fullpath, RTLD_LAZY);
            if (!h) { fprintf(stderr, "dlopen failed: %s\n", dlerror()); continue; }
            const char *(*getname)(void) = dlsym(h, "module_name");
            int (*initf)(void) = dlsym(h, "module_init");
            int (*processf)(const unsigned char*, size_t, unsigned char**, size_t*) = dlsym(h, "module_process");
            void (*freef)(void) = dlsym(h, "module_free");
            if (!getname || !processf) {
                fprintf(stderr, "Module %s missing required symbols\n", d->d_name);
                dlclose(h);
                continue;
            }
            module_entry_t *entry = calloc(1, sizeof(*entry));
            entry->name = strdup(getname());
            entry->handle = h;
            entry->init = initf;
            entry->process = processf;
            entry->cleanup = freef;
            if (entry->init && entry->init() != 0) {
                fprintf(stderr, "Module %s init failed\n", d->d_name);
                dlclose(h); free(entry->name); free(entry);
                continue;
            }
            add_module(entry);
            fprintf(stderr, "Loaded module: %s (file=%s)\n", entry->name, fullpath);
        }
    }
    closedir(dir);
}

static void unload_modules(void) {
    module_entry_t *cur = modules_head;
    while (cur) {
        if (cur->cleanup) cur->cleanup();
        dlclose(cur->handle);
        free(cur->name);
        module_entry_t *n = cur->next;
        free(cur);
        cur = n;
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file> [modules_dir]\n", argv[0]);
        return 1;
    }
    const char *file = argv[1];
    const char *modules_dir = (argc >= 3) ? argv[2] : "modules";

    unsigned char *buf = NULL;
    size_t buflen = 0;
    if (load_file_to_memory(file, &buf, &buflen) < 0) {
        perror("load_file_to_memory");
        return 1;
    }
    fprintf(stderr, "Loaded file '%s' (%zu bytes)\n", file, buflen);

    load_modules_from_dir(modules_dir);

    for (module_entry_t *m = modules_head; m; m = m->next) {
        fprintf(stderr, "Running module: %s\n", m->name);
        unsigned char *out = NULL;
        size_t outlen = 0;
        if (m->process(buf, buflen, &out, &outlen) == 0) {
            char outname[512];
            snprintf(outname, sizeof(outname), "%s.%s.out", file, m->name);
            FILE *fp = fopen(outname, "wb");
            if (fp) {
                fwrite(out, 1, outlen, fp);
                fclose(fp);
                fprintf(stderr, "Wrote: %s\n", outname);
            }
            free(out);
        } else {
            fprintf(stderr, "Module %s failed\n", m->name);
        }
    }

    unload_modules();
    free(buf);
    return 0;
}
