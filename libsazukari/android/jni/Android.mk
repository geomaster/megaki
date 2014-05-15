LOCAL_PATH := $(call my-dir)


# libsazukari
include $(CLEAR_VARS)
APP_PLATFORM := android-9

LOCAL_MODULE           := libsazukari
LOCAL_SRC_FILES        := libsazukari/src/sazukari.c \
                          libsazukari/src/common.c \
                          libsazukari/src/sslc.c
LOCAL_CFLAGS           := -Ijni/libsazukari/include \
                          -Ijni/deps/openssl/include \
                          -Ljni/deps/lib

include $(BUILD_STATIC_LIBRARY)

# libsazukarinative
include $(CLEAR_VARS)
APP_PLATFORM := android-9

LOCAL_MODULE           := libsazukarinative
LOCAL_SRC_FILES        := sazukarinative/src/sazukarinative.c
LOCAL_STATIC_LIBRARIES := libsazukari jni/deps/lib/libcrypto.a
LOCAL_CFLAGS           := -Ijni/libsazukari/include \
                          -Ijni/sazukarinative/include
LOCAL_LDLIBS           := -llog \
                          -lcrypto
LOCAL_LDFLAGS          := -Ljni/deps/lib \


include $(BUILD_SHARED_LIBRARY)

