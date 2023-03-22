#include <jni.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <fstream>
#include "dumpdll.h"
#include "MonoImage.h"

MonoMethodHeader* (*mono_metadata_parse_mh) (MonoImage*, const char*) = NULL;
MonoImage* (*mono_image_open_from_data_with_name)(char*, int, int, void*, int, char*) = NULL;
MonoMethodHeader* (*ori_mono_metadata_parse_mh_full)(MonoImage*, void*, const char*) = NULL;

#define dumpdll
#if defined(decdll)
static bool needDecrypted = true;
jstring(*ori_getDataSign)(JNIEnv *, jobject, jint, jstring, jint) = NULL;
jstring new_getDataSign(JNIEnv *env, jobject a2, jint a3, jstring text, jint needEncrypt) {
    if (needDecrypted) {
        decrypt();
        needDecrypted = false;
    }
    return ori_getDataSign(env, a2, a3, text, needEncrypt);
}
void* (*ori_mono_runtime_invoke)(void*, void*, void**, void**) = nullptr;
void* new_mono_runtime_invoke(void* method, void* obj, void** params, void** exec) {
    LOGD("new_mono_runtime_invoke called");
    if (needDecrypted) {
        decrypt();
        needDecrypted = false;
    }
    return ori_mono_runtime_invoke(method, obj, params, exec);
}
#endif

void* thereisnothing (void *args)
{
    LOGD ("**** new thread: [%d] ****", gettid ());
    sleep (5);
    void* handle = dlopen("libmono.so", 0);
    if (!handle) {
        LOGD("%s", dlerror());
    }
#if defined(decdll)
    //void* mono_runtime_invoke_addr = dlsym(handle, "mono_runtime_invoke");
    long neteaseLibAddr = get_module_base("libNetHTProtect.so") + 0x11BDA0;
    if (neteaseLibAddr) {
        void* filehandle = dlopen("/system/lib/libsubstrate.so", RTLD_LAZY);
        if (filehandle != NULL) {
            mshook = (void(*)(void *, void *, void **))dlsym(filehandle, "MSHookFunction");
        }
        else {
            LOGD("failed to open Cydia so");
        }
        /* You cannot run decrypt on thread */
        mono_image_open_from_data_with_name = (MonoImage*(*)(char *, int, int, void *, int, char *))dlsym(handle, "mono_image_open_from_data_with_name");
        ori_mono_metadata_parse_mh_full = (MonoMethodHeader*(*)(MonoImage *, void*, const char *))dlsym(handle, "mono_metadata_parse_mh_full");
        mshook((void*)neteaseLibAddr, (void*)&new_getDataSign, (void**)&ori_getDataSign);
    }
    else {
        LOGD("mono_runtime_invoke_addr invailed");
    }
#endif
#if defined(dumpdll)
    mono_image_open_from_data_with_name = (MonoImage*(*)(char *, int, int, void *, int, char *))dlsym(handle, "mono_image_open_from_data_with_name");
    FILE * pFile = fopen("/data/local/tmp/Assembly-CSharp.dll", "rb");
    fseek(pFile, 0, SEEK_END);
    long lSize = ftell(pFile);
    rewind(pFile);
    char * buffer = (char *)malloc(sizeof(char)*lSize);
    fread(buffer, 1, lSize, pFile);
    fclose(pFile);

    MonoImageOpenStatus status;
    MonoImage* image = mono_image_open_from_data_with_name(buffer, lSize, 1, &status, 0, "Assembly-CSharp.dll");

    LOGD("name: %s", image->name);
    LOGD("guid: %s", image->guid);

    MonoCLIImageInfo* iinfo = image->image_info;
    LOGD("pe_cli_header.rva: %X", iinfo->cli_header.datadir.pe_cli_header.rva);
    LOGD("coff_sections: %d", iinfo->cli_header.coff.coff_sections);
    LOGD("coff_opt_header_size: %X", iinfo->cli_header.coff.coff_opt_header_size);
    LOGD("coff_attributes: %X", iinfo->cli_header.coff.coff_attributes);
    LOGD("ch_metadata.rva: %X", iinfo->cli_cli_header.ch_metadata.rva);
    LOGD("ch_metadata.size: %X", iinfo->cli_cli_header.ch_metadata.size);
    LOGD("cli_sections: %p", iinfo->cli_sections[0]);
    //for (int i = 0; i < 10; ++i) {
    //    LOGD("%X", image->tables[i].rows);
    //}

    //unsigned char* ptr = (unsigned char*)(t.base + t.row_size);
    //LOGD("%X %X %X %X %X %X %X %X", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7]);
    /* Write raw to file */
    /*
    FILE* file = fopen("/data/local/tmp/dump2.dll", "wb+");
    if (file != NULL) {
        fwrite(image->raw_data, 1, image->raw_data_len, file);
        fclose(file);
        LOGD("dump file successfully!!");
    }
    */
    //std::ofstream heap_strings("/data/local/tmp/heap_strings", std::ios::binary);
    //heap_strings.write(image->heap_strings.data, image->heap_strings.size);
    //heap_strings.close();

    //std::ofstream heap_us("/data/local/tmp/heap_us", std::ios::binary);
    //heap_us.write(image->heap_us.data, image->heap_us.size);
    //heap_us.close();

    //std::ofstream heap_blob("/data/local/tmp/heap_blob", std::ios::binary);
    //heap_blob.write(image->heap_blob.data, image->heap_blob.size);
    //heap_blob.close();

    //std::ofstream heap_guid("/data/local/tmp/heap_guid", std::ios::binary);
    //heap_guid.write(image->heap_guid.data, image->heap_guid.size);
    //heap_guid.close();

    //std::ofstream heap_tables("/data/local/tmp/heap_tables", std::ios::binary);
    //heap_tables.write(image->heap_tables.data, image->heap_tables.size);
    //heap_tables.close();

    //std::ofstream heap_pdb("/data/local/tmp/heap_pdb", std::ios::binary);
    //heap_pdb.write(image->heap_pdb.data, image->heap_pdb.size);
    //heap_pdb.close();

#endif
    /*int count = 0;
    while (true)
    {
        long mono_base = get_module_base ("libmono.so");
        long neteaseLibAddr = get_module_base ("libNetHTProtect.so");
        if (mono_base != 0)
        {
             void* filehandle = dlopen ("/system/lib/libsubstrate.so", RTLD_LAZY);
             if (filehandle != NULL)
                 mshook = (void (*)(void *, void *, void **))dlsym (filehandle, "MSHookFunction");
             else
                 LOGD ("failed to open Cydia so");
             long getDataSignAddr = neteaseLibAddr + 0x11BDA0;
             if (mshook != NULL)
             {
                 LOGD ("Hook function...");
                 mshook ((void*)getDataSignAddr, (void*)&new_getDataSign, (void**)&ori_getDataSign);
                 LOGD ("Success(maybe");
             }
             else
             {
                 LOGD ("Failed to find mshook address");
             }
            //mono_metadata_parse_mh = (MonoMethodHeader*(*)(MonoImage *, const char *))(mono_base + 0x1ED7B3);
            mono_image_open_from_data_with_name = (MonoImage*(*)(char *, int, int, void *, int, char *))(mono_base + 0x1C34E3);
            ori_mono_metadata_parse_mh_full = (MonoMethodHeader*(*)(MonoImage *, void*, const char *))(mono_base + 0x1D140);//0x1CDF0 0x1EA632
            //decrypt();
            //mshook((void*)(mono_base + 0x1D140), (void*)&new_mono_metadata_parse_mh_full, (void**)&ori_mono_metadata_parse_mh_full);
            break;
        }
        else
        {
            count++;
            sleep (1);
            if (count > 10)
            {
                LOGD ("**** find module base address failed ****");
                break;
            }
        }
    }*/
    return ((void *)0);
}
#if defined(decdll)
void memcpydiy (char *dest, const char *scr, int len)
{
    if (dest == NULL || scr == NULL)
        return;
    char *pdest = dest;
    char *pscr = (char *)scr;
    if ((scr < dest) && (dest < scr + len))  //重叠，从尾部开始复制
    {
        pdest = pdest + len - 1;
        pscr = pscr + len - 1;
        while (len--)
        {
            *pdest-- = *pscr--;
        }
    }
    else
    {
        while (len--)
        {
            *pdest++ = *pscr++;
        }
    }
}

int decrypt () {
    LOGD("*** decrypt called ***");
#pragma region open dll
    FILE * pFile = fopen ("/data/local/tmp/dump2.dll", "rb");
    fseek (pFile, 0, SEEK_END);
    long lSize = ftell (pFile);
    rewind (pFile);
    char * buffer = (char *)malloc (sizeof(char)*lSize);
    fread (buffer, 1, lSize, pFile);
    fclose (pFile);

    //call mono_image_open_from_data_with_name
    MonoImageOpenStatus status;
    MonoImage* result = mono_image_open_from_data_with_name(buffer, lSize, 1, &status, 0, "dll");
    if (status != MONO_IMAGE_OK) {
        LOGD ("Mono image return error");
    }
    LOGD ("m->raw_data: %02X %02X %02X %02X", (unsigned char)result->raw_data[0], (unsigned char)result->raw_data[1], (unsigned char)result->raw_data[2], (unsigned char)result->raw_data[3]);
#pragma endregion
    /* 18bytes
    * 0x00-0x04 -> RVA
    * 0x05-0x06 -> ImplFlags
    * 0x07-0x08 -> Flags
    * 0x09-0x12 -> Name
    * 0x13-0x16 -> Signature
    * 0x17-0x18 -> ParamList
    */
    
    //long MethodDefStartAddr = 0x0054EE40;
    //long MethodDefEndAddr = 0x0065B982;
     //   int Method_RVA = 0x0;
     //   int Section_RVA = 0x2000;
     //   int File_Location = 0x200;
     //   int offset = 0x0;

    long MethodDefStartAddr = 0x0001BA74;
    long MethodDefEndAddr = 0x0002368A;
    int Method_RVA = 0x0;
    int Section_RVA = 0x2000;
    int File_Location = 0x200;
    int offset = 0x0;

    char* ptr = result->raw_data;
    char* _ptr = ptr;
    ptr += MethodDefStartAddr;

    for (int i = 0; i < ((MethodDefEndAddr - MethodDefStartAddr)/14); ++i)
    {
        ptr += (14 * i);
        Method_RVA = read32 ((unsigned char*)ptr);
        if (Method_RVA > 0)
        {
            //LOGD("****************************");
            //(Method RVA - Section RVA) + File Location
            offset = Method_RVA - Section_RVA + File_Location;
            //LOGD("Method_RVA: 0x%02X", Method_RVA);
            ptr = _ptr;
            ptr += offset;
            //LOGD ("Proto pointer: %02X %02X %02X %02X %02X %02X",
            //    (unsigned char)ptr[0], (unsigned char)ptr[1], (unsigned char)ptr[2],
            //    (unsigned char)ptr[3], (unsigned char)ptr[4], (unsigned char)ptr[5]);

            MonoMethodHeader *res = (struct MonoMethodHeader*)malloc(sizeof(MonoMethodHeader));
            res = ori_mono_metadata_parse_mh_full (result, 0, (const char*)ptr/*, error*/);
            //LOGD ("res->code_size: %02X", res->code_size);
            //LOGD ("res->code: %02X %02X %02X %02X %02X %02X",
            //    res->code[0], res->code[1], res->code[2],
            //    res->code[3], res->code[4], res->code[5]);
             unsigned char flags = *(const unsigned char *)ptr;
             unsigned char format = flags & METHOD_HEADER_FORMAT_MASK;
             switch (format) {
                 case METHOD_HEADER_TINY_FORMAT:
                     ptr++;
                     break;
                 case METHOD_HEADER_FAT_FORMAT:
                     ptr += 12;
                     break;
             }
             memcpydiy (ptr, (const char*)res->code, res->code_size);
             //LOGD("After pointer: %02X %02X %02X %02X %02X %02X",
                // (unsigned char)ptr[0], (unsigned char)ptr[1], (unsigned char)ptr[2],
                // (unsigned char)ptr[3], (unsigned char)ptr[4], (unsigned char)ptr[5]);
        }
        ptr = _ptr;
        ptr += MethodDefStartAddr;
    }
    
    ptr = _ptr;
    FILE *dfile = fopen("/data/local/tmp/fixed2.dll", "wb+");
    if (dfile != NULL) {
        fwrite (result->raw_data, 1, result->raw_data_len, dfile);
        fclose(dfile);
        LOGD("decrypt file successfully!!");
    }
    return 0;
}
#endif
__attribute__((constructor))
void init() {
    int temp;
    pthread_t ntid;
    if ((temp = pthread_create(&ntid, NULL, thereisnothing, NULL))) {
        LOGD("can't create thread");
    }
}