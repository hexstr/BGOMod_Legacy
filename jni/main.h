#ifndef LOG_TAG
#define LOG_TAG    "ethereal"
#include <errno.h>
#include "android/log.h"
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#endif
#include "MonoImage.h"
void(*MSHookFunction)(void*, void*, void**) = nullptr;
void DumpHex(unsigned char* ptr, int line, int longLine = 0) {
        if (longLine) {
            for (int i = 0; i < line; ++i) {
                LOGD("%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                    ptr[i * 0x10], ptr[i * 0x10 + 1], ptr[i * 0x10 + 2], ptr[i * 0x10 + 3],
                    ptr[i * 0x10 + 4], ptr[i * 0x10 + 5], ptr[i * 0x10 + 6], ptr[i * 0x10 + 7],
                    ptr[i * 0x10 + 8], ptr[i * 0x10 + 9], ptr[i * 0x10 + 0xA], ptr[i * 0x10 + 0xB],
                    ptr[i * 0x10 + 0xC], ptr[i * 0x10 + 0xD], ptr[i * 0x10 + 0xE], ptr[i * 0x10 + 0xF]);
            }
        }
        else {
            for (int i = 0; i < line; ++i) {
                LOGD("%02X %02X %02X %02X", ptr[i * 4], ptr[i * 4 + 1], ptr[i * 4 + 2], ptr[i * 4 + 3]);
            }
        }
    }
//mono export func
typedef void* (*mono_get_root_domain_t)();
typedef void* (*mono_thread_attach_t)(void* mDomain);
typedef void* (*mono_image_open_from_data_t) (char *data, uint32_t data_len, int32_t need_copy, MonoImageOpenStatus *status);
typedef void* (*mono_assembly_load_from_full_t)(void *image, const char *fname, MonoImageOpenStatus *status, int32_t refonly);
typedef void* (*mono_class_from_name_t)(void* image, const char* name_space, const char* name);
typedef void* (*mono_object_new_t)(void* mDomain, void* klass);
typedef void* (*mono_runtime_object_init_t)(void* MonoObject);
//end