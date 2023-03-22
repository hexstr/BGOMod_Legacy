LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE     := com.bilibili.fatego
LOCAL_LDLIBS += -ldl -llog
LOCAL_LDFLAGS := -Wl
LOCAL_SRC_FILES:= dumpdll.cpp#main.cpp
include $(BUILD_SHARED_LIBRARY)