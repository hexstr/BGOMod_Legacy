#define LOG_TAG    "ethereal"
#include <errno.h>
#include "android/log.h"
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

/*mono defind*/
#define METHOD_HEADER_FORMAT_MASK   3
#define METHOD_HEADER_TINY_FORMAT   2
#define METHOD_HEADER_FAT_FORMAT    3
#define METHOD_HEADER_INIT_LOCALS   0x10
#define METHOD_HEADER_MORE_SECTS    0x08
typedef unsigned short guint16;
typedef unsigned int guint32;
#ifndef MONO_ZERO_LEN_ARRAY
#ifdef __GNUC__
#define MONO_ZERO_LEN_ARRAY 0
#else
#define MONO_ZERO_LEN_ARRAY 1
#endif
#endif
typedef union {
    char c[2];
    guint16 i;
} mono_rint16;
typedef union {
    char c[4];
    guint32 i;
} mono_rint32;
guint16
read16(const unsigned char *x)
{
    mono_rint16 r;
    r.c[0] = x[0];
    r.c[1] = x[1];
    return r.i;
}
guint32
read32(const unsigned char *x)
{
    mono_rint32 r;
    r.c[0] = x[0];
    r.c[1] = x[1];
    r.c[2] = x[2];
    r.c[3] = x[3];
    return r.i;
}
typedef unsigned short guint16;
typedef unsigned int guint32;
struct MonoMethodHeader {
    guint16      code_size;
    const unsigned char  *code;
    guint16      max_stack : 15;
    unsigned int is_transient : 1; /* mono_metadata_free_mh () will actually free this header */
    unsigned int num_clauses : 15;
    /* if num_locals != 0, then the following apply: */
    unsigned int init_locals : 1;
    guint16      num_locals;
    void *clauses;
    void  *volatile_args;
    void  *volatile_locals;
    void    *locals[MONO_ZERO_LEN_ARRAY];
};
//struct MonoImage {
//    int ref_count;
//    void *raw_data_handle;
//    char *raw_data;
//    int raw_data_len;
//};
//typedef enum {
//    MONO_IMAGE_OK,
//    MONO_IMAGE_ERROR_ERRNO,
//    MONO_IMAGE_MISSING_ASSEMBLYREF,
//    MONO_IMAGE_IMAGE_INVALID
//} MonoImageOpenStatus;

long get_module_base(const char* libname) {
    FILE *fp;
    char *pch;
    long addr = 0;
    char filename[32];
    char line[1024];
    snprintf(filename, sizeof(filename), "/proc/self/maps");
    fp = fopen(filename, "r");
    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, libname)) {
                pch = strtok(line, "-");
                addr = strtoul(pch, NULL, 16);
                if (addr == 0x8000)
                    addr = 0;
                break;
            }
        }
        fclose(fp);
    }
    return addr;
}

void(*mshook) (void *symbol, void *replace, void **result) = NULL;
int decrypt();