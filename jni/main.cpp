#include <pthread.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fstream>
#include "main.h"

int GetLibAddr(const char* libname) {
        FILE *fp = fopen("/proc/self/maps", "r");
        char *pch;
        long addr = 0;
        char line[1024];
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

int inject () {
    /* Define function address */
    void* handle = dlopen("libmono.so", 0);
    LOGD("handle: %p", handle);
    mono_get_root_domain_t mono_get_root_domain = (mono_get_root_domain_t)dlsym(handle, "mono_get_root_domain");
    mono_thread_attach_t mono_thread_attach = (mono_thread_attach_t)dlsym(handle, "mono_thread_attach");
    mono_class_from_name_t mono_class_from_name = (mono_class_from_name_t)dlsym(handle, "mono_class_from_name");
    mono_object_new_t mono_object_new = (mono_object_new_t)dlsym(handle, "mono_object_new");
    mono_runtime_object_init_t mono_runtime_object_init = (mono_runtime_object_init_t)dlsym(handle, "mono_runtime_object_init");
    
    void* handle2 = dlopen("/system/lib/orimono.so", 0);
    LOGD("handle2: %p", handle2);
    mono_image_open_from_data_t mono_image_open_from_data = (mono_image_open_from_data_t)dlsym(handle2, "mono_image_open_from_data");
    mono_assembly_load_from_full_t mono_assembly_load_from_full = (mono_assembly_load_from_full_t)dlsym(handle2, "mono_assembly_load_from_full");
    
    FILE * pFile = fopen ("/data/local/tmp/BetterGameOptions.dll", "rb");
    if (pFile != NULL) {
        fseek (pFile, 0, SEEK_END);
        long lSize = ftell (pFile);
        rewind (pFile);
        char * buffer = (char *)malloc (sizeof(char)*lSize);
        fread (buffer, 1, lSize, pFile);
        fclose (pFile);
        //Call 'ctor.Loader' in C#
        LOGD("Call '.ctor.Loader' in C#");
        mono_thread_attach (mono_get_root_domain ());
        MonoImageOpenStatus status;
        void* image = mono_image_open_from_data (buffer, lSize, 1, &status);
        mono_assembly_load_from_full (image, "BetterGameOptions", &status, 0);
        void* pClass = mono_class_from_name (image, "BetterGameOptions", "Loader");
        void* method = mono_object_new (mono_get_root_domain (), pClass);
        mono_runtime_object_init (method);
        if (status != MONO_IMAGE_OK) {
            LOGD ("Failed to load plugin");
            return -1;
        }
        LOGD ("Plugin has been loaded");
    }
    return 0;
}

int (*ori_mono_image_load_pe_data)(MonoImage*, int (*)(MonoImage *, int, guint32 *)) = nullptr;
int new_mono_image_load_pe_data(MonoImage* image, int (*mono_metadata_compute_size)(MonoImage*, int, guint32*)) {
    int ret = ori_mono_image_load_pe_data(image, mono_metadata_compute_size);
    if(strstr(image->name, "Assembly-CSharp.dll")) {
        LOGD("name: %s", image->name);
        LOGD("version: %s", image->version);
        LOGD("md_version_major: %d", image->md_version_major);
        MonoCLIImageInfo* iinfo = image->image_info;
        LOGD("pe_cli_header.rva: %X", iinfo->cli_header.datadir.pe_cli_header.rva);
        LOGD("coff_sections: %d", iinfo->cli_header.coff.coff_sections);
        LOGD("coff_opt_header_size: %X", iinfo->cli_header.coff.coff_opt_header_size);
        LOGD("coff_attributes: %X", iinfo->cli_header.coff.coff_attributes);
        LOGD("ch_metadata.rva: %X", iinfo->cli_cli_header.ch_metadata.rva);
        LOGD("ch_metadata.size: %X", iinfo->cli_cli_header.ch_metadata.size);
        LOGD("ch_flags: %X", iinfo->cli_cli_header.ch_flags);
        //const int top = iinfo->cli_header.coff.coff_sections;
        //LOGD("cli_section_count: %d", iinfo->cli_section_count);
        //for (int i = 0; i < 3; ++i) {
        //    MonoSectionTable* t = &iinfo->cli_section_tables[i];
        //    LOGD("st_virtual_size: %X", t->st_virtual_size);
        //    LOGD("st_virtual_address: %X", t->st_virtual_address);
        //    LOGD("st_raw_data_size: %X", t->st_raw_data_size);
        //    LOGD("st_raw_data_ptr: %X", t->st_raw_data_ptr);
        //    LOGD("st_name: %s", t->st_name);
        //}

        //unsigned char* ptr = (unsigned char*)t->st_raw_data_ptr;
        //LOGD("%X %X %X %X %X %X %X %X", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7]);
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
    }
    return ret;
}

void* thereisnothing(void *args) {
    LOGD("***** new thread *****");
    LOGD("***** begin *****");
    //inject ();
    //sleep(5);
    void* filehandle = dlopen("/system/lib/libsubstrate.so", RTLD_LAZY);
    if (filehandle != NULL)
        MSHookFunction = (void(*)(void*, void*, void**))dlsym(filehandle, "MSHookFunction");
    else {
        LOGD("failed to open Cydia so");
        exit(0);
    }
    int baseaddr = 0;
    while (!baseaddr) {
        baseaddr = GetLibAddr("libNetHTProtect.so");
    }
    int mono_image_load_pe_data_addr = 0x9A8B0 + baseaddr;
    LOGD("mono_image_load_pe_data_addr: %X", mono_image_load_pe_data_addr);
    MSHookFunction((void*)mono_image_load_pe_data_addr, (void*)new_mono_image_load_pe_data, (void**)&ori_mono_image_load_pe_data);
    
    //void* handle = dlopen("libmono.so", 0);
    //LOGD("handle: %p", handle);
    //mono_get_root_domain_t mono_get_root_domain = (mono_get_root_domain_t)dlsym(handle, "mono_get_root_domain");
    //mono_thread_attach_t mono_thread_attach = (mono_thread_attach_t)dlsym(handle, "mono_thread_attach");
    //mono_class_from_name_t mono_class_from_name = (mono_class_from_name_t)dlsym(handle, "mono_class_from_name");
    //mono_object_new_t mono_object_new = (mono_object_new_t)dlsym(handle, "mono_object_new");
    //mono_runtime_object_init_t mono_runtime_object_init = (mono_runtime_object_init_t)dlsym(handle, "mono_runtime_object_init");
    //mono_image_open_from_data_t mono_image_open_from_data = (mono_image_open_from_data_t)dlsym(handle, "mono_image_open_from_data");
    //mono_assembly_load_from_full_t mono_assembly_load_from_full = (mono_assembly_load_from_full_t)dlsym(handle, "mono_assembly_load_from_full");
    //FILE* pFile = fopen("/data/local/tmp/Assembly-CSharp.dll", "rb");
    //if (pFile != NULL) {
    //    fseek(pFile, 0, SEEK_END);
    //    long lSize = ftell(pFile);
    //    rewind(pFile);
    //    char* buffer = (char*)malloc(sizeof(char) * lSize);
    //    fread(buffer, 1, lSize, pFile);
    //    fclose(pFile);
    //    mono_thread_attach(mono_get_root_domain());
    //    MonoImageOpenStatus status;
    //    void* image = mono_image_open_from_data(buffer, lSize, 1, &status);
    //}
    //LOGD ("***** finish *****");
    return 0;
}

__attribute__((constructor))
void init() {
    int temp;
    pthread_t ntid;
    if ((temp = pthread_create(&ntid, NULL, thereisnothing, NULL))) {
        LOGD("can't create thread");
    }
}