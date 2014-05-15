/* welcome to a world of chaos
 *
 * you've been caught in the light
 */
#include <sazukari.h>
#include <jni.h>
#include <string.h>
#include <android/log.h>

#define MAX_SAZUKARI_CONTEXTS			128

typedef struct sn_szkr_ctx_t {
	szkr_ctx_t* sazukari;
	int socket;
	byte* resbuf;
	length_t resbufsz;
} sn_szkr_ctx_t;

enum sn_methods {
	sn_SocketRead,
	sn_SocketWrite,
	SN_METHODCOUNT
};

typedef struct sn_method_desc_t {
	char *name,
	     *sig;
} sn_method_desc_t;

static sn_szkr_ctx_t g_contexts[MAX_SAZUKARI_CONTEXTS];
static jclass g_myclass;
static jmethodID g_methods[SN_METHODCOUNT];
static JNIEnv* g_env;
static int g_lasthandle;

static sn_method_desc_t g_methoddesc[] = {
	{ .name = "_snSocketRead",
	  .sig = "(ILjava/nio/ByteBuffer;J)J"
	},
	{ .name = "_snSocketWrite",
	  .sig = "(ILjava/nio/ByteBuffer;J)J"
	}
};

slength_t socket_rd(byte* buf, length_t sz, void* param)
{
	sn_szkr_ctx_t* p = (sn_szkr_ctx_t*) param;

	jobject jbuf = (*g_env)->NewDirectByteBuffer(g_env, buf, sz);
	if (!jbuf) {
		__android_log_print(ANDROID_LOG_WARN, "SAZUKARI", "Could not allocate ByteBuffer");
		return(-1);
	}

	return (*g_env)->CallStaticLongMethod(g_env, g_myclass, g_methods[sn_SocketRead], p->socket, jbuf, (jlong) sz);
}

slength_t socket_wr(byte* buf, length_t sz, void* param)
{
	sn_szkr_ctx_t* p = (sn_szkr_ctx_t*) param;
	__android_log_print(ANDROID_LOG_WARN, "SAZUKARI", "we rowdy");

	jobject jbuf = (*g_env)->NewDirectByteBuffer(g_env, buf, sz);
	if (!jbuf) {
		__android_log_print(ANDROID_LOG_WARN, "SAZUKARI", "Could not allocate ByteBuffer");
		return(-1);
	}

	return (*g_env)->CallStaticLongMethod(g_env, g_myclass, g_methods[sn_SocketWrite], p->socket, jbuf, (jlong) sz);
}

jint JNI_OnLoad(JavaVM* vm, void* nothing)
{
	__android_log_print(ANDROID_LOG_DEBUG, "SAZUKARI", "Initializing libsazukarinative");

	JNIEnv* env;
	if ((*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_6) != JNI_OK) {
		__android_log_print(ANDROID_LOG_WARN, "SAZUKARI", "GetEnv failed");
		goto failure;
	};
	g_env = env;

	jclass parent = (*env)->FindClass(env, "com/nmi/sazukari/SazukariNative");
	if (!parent) {
		__android_log_print(ANDROID_LOG_WARN, "SAZUKARI", "Could not find parent class");
		goto failure;
	}

	g_myclass = (jclass) (*env)->NewGlobalRef(env, parent);
	if (!g_myclass) {
		goto failure;
	}

	int i;
	for (i = 0; i < SN_METHODCOUNT; ++i) {
		jmethodID id = (*env)->GetStaticMethodID(env, parent, g_methoddesc[i].name, g_methoddesc[i].sig);
		if (!id) {
			__android_log_print(ANDROID_LOG_WARN, "SAZUKARI", "Method %s[%s] not found",
					g_methoddesc[i].name, g_methoddesc[i].sig);
			goto destroy_ref;
		}
		g_methods[i] = id;
	}

	return(JNI_VERSION_1_6);

destroy_ref:
	(*env)->DeleteGlobalRef(env, g_myclass);

failure:
	return(JNI_ERR);

}

JNIEXPORT jint JNICALL Java_com_nmi_sazukari_SazukariNative__1szkrInitialize
	(JNIEnv* env, jclass clazz)
{
	if (szkr_init() != 0) {
		__android_log_print(ANDROID_LOG_WARN, "SAZUKARI", "szkr_init() failed");
		return(-1);
	};

	g_lasthandle = 0;
	return( 0 );
}

jint Java_com_nmi_sazukari_SazukariNative__1szkrNewContext
	(JNIEnv* env, jobject thiz, jint sockHandle, jobject skey)
{
	jbyte* skeybuf = (*env)->GetDirectBufferAddress(env, skey);
	jlong skeybufsize = (*env)->GetDirectBufferCapacity(env, skey);

	if (!skeybuf || skeybufsize < sizeof(szkr_srvkey_t) || skeybufsize == -1) {
		__android_log_print(ANDROID_LOG_WARN, "SAZUKARI", "Server key buffer anomaly");
		goto failure;
	}

	int ctxhandle = g_lasthandle;
	if (ctxhandle >= MAX_SAZUKARI_CONTEXTS) {
		__android_log_print(ANDROID_LOG_WARN, "SAZUKARI", "Maximum number of handles reached");
		goto failure;
	}

	szkr_ctx_t* ctx = (szkr_ctx_t*) malloc(szkr_get_ctxsize());
	if (!ctx) {
		__android_log_print(ANDROID_LOG_WARN, "SAZUKARI", "Could not allocate memory for context");
		goto failure;
	}

	szkr_iostream_t ios = {
		.read_callback = &socket_rd,
		.write_callback = &socket_wr,
		.cb_param = &g_contexts[ctxhandle]
	};

	szkr_srvkey_t srvkey;
	memcpy(&srvkey, skeybuf, sizeof(szkr_srvkey_t));

	if (szkr_new_ctx(ctx, ios, srvkey) != 0) {
		__android_log_print(ANDROID_LOG_WARN, "SAZUKARI", "szkr_new_ctx() failed");
		goto dealloc_ctx;
	}

	g_contexts[ctxhandle].sazukari = ctx;
	g_contexts[ctxhandle].socket = sockHandle;
	g_contexts[ctxhandle].resbuf = NULL;

	++g_lasthandle;

	return(ctxhandle);

dealloc_ctx:
	free(ctx);

failure:
	return(-1);
}

jlong Java_com_nmi_sazukari_SazukariNative__1szkrGetSessionDataSize(JNIEnv* env, jclass clazz)
{
	return( szkr_get_session_data_size() );
}

jint Java_com_nmi_sazukari_SazukariNative__1szkrGetSessionData(JNIEnv* env, jclass clazz, jint ctxHandle,
		jobject outSessionData)
{
	szkr_ctx_t* ctx = g_contexts[ctxHandle].sazukari;

	jbyte* buf = (*env)->GetDirectBufferAddress(env, outSessionData);
	jlong bufsize = (*env)->GetDirectBufferCapacity(env, outSessionData);
	if (!buf || bufsize < szkr_get_session_data_size()) {
		__android_log_print(ANDROID_LOG_WARN, "SAZUKARI", "Session data buffer anomaly");
		goto failure;
	}

	length_t len = bufsize;
	return( szkr_get_session_data(ctx, (byte*) buf, &len) );

failure:
	return( -1 );
}

jint Java_com_nmi_sazukari_SazukariNative__1szkrResetContext(JNIEnv* env, jclass clazz, int ctxHandle)
{
	szkr_ctx_t* ctx = g_contexts[ctxHandle].sazukari;
	return( szkr_reset_ctx(ctx) );
}

jint Java_com_nmi_sazukari_SazukariNative__1szkrHandshake(JNIEnv* env, jclass clazz, int ctxHandle)
{
	szkr_ctx_t* ctx = g_contexts[ctxHandle].sazukari;
	__android_log_print(ANDROID_LOG_WARN, "SAZUKARI", "we handshake now %p", ctx);
	return( szkr_do_handshake(ctx) );
}

jint Java_com_nmi_sazukari_SazukariNative__1szkrLastError(JNIEnv* env, jclass clazz, int ctxHandle)
{
	szkr_ctx_t* ctx = g_contexts[ctxHandle].sazukari;
	return (jint) szkr_last_error(ctx);
}

jint Java_com_nmi_sazukari_SazukariNative__1szkrResume(JNIEnv* env, jclass clazz,
		int ctxHandle, jobject sessionData)
{
	szkr_ctx_t* ctx = g_contexts[ctxHandle].sazukari;
	jbyte *buf = (*env)->GetDirectBufferAddress(env, sessionData);
	jlong bufsize = (*env)->GetDirectBufferCapacity(env, sessionData);
	if (!buf || bufsize < szkr_get_session_data_size()) {
		goto failure;
	}

	return( szkr_resume_session(ctx, buf) );

failure:
	return( -1 );
}

jlong Java_com_nmi_sazukari_SazukariNative__1szkrSendMessage(JNIEnv* env, jclass clazz,
		int ctxHandle, jobject msg)
{
	szkr_ctx_t* ctx = g_contexts[ctxHandle].sazukari;
	jbyte* buf = (*env)->GetDirectBufferAddress(env, msg);
	jlong msglen = (*env)->GetDirectBufferCapacity(env, msg);

	if (!buf || msglen <= 0) {
		__android_log_print(ANDROID_LOG_WARN, "SAZUKARI", "Message buffer anomaly");
		goto failure;
	}

	byte* msgbuf = malloc(msglen + SAZUKARI_MIN_BUFFER_SENTINEL);
	if (!msgbuf) {
		__android_log_print(ANDROID_LOG_WARN, "SAZUKARI", "Failed to allocate message buffer");
		goto failure;
	}

	memcpy(msgbuf, buf, msglen);
	byte* respbuf = NULL;
	length_t resplen;
	if (szkr_send_message(ctx, msgbuf, msglen, &respbuf, &resplen) != 0) {
		__android_log_print(ANDROID_LOG_WARN, "SAZUKARI", "szkr_send_message() failed");
		goto dealloc_msgbuf;
	}

	if (g_contexts[ctxHandle].resbuf)
		free(g_contexts[ctxHandle].resbuf);

	g_contexts[ctxHandle].resbuf = respbuf;
	g_contexts[ctxHandle].resbufsz = resplen;

	return( 0 );

dealloc_msgbuf:
	free(msgbuf);

failure:
	return( -1 );
}

jobject Java_com_nmi_sazukari_SazukariNative__1szkrAccessResponseBuffer(JNIEnv* env, jclass clazz, int ctxHandle)
{
	sn_szkr_ctx_t* sc = &g_contexts[ctxHandle];
	if (!sc->resbuf) {
		return( NULL );
	}

	return( (*env)->NewDirectByteBuffer(env, sc->resbuf, sc->resbufsz) );
}

void Java_com_nmi_sazukari_SazukariNative__1szkrDestroyResponseBuffer(JNIEnv* env, jclass clazz, int ctxHandle)
{
	sn_szkr_ctx_t* sc = &g_contexts[ctxHandle];
	if (sc->resbuf) {
		free(sc->resbuf);
		sc->resbuf = NULL;
	}
}

void Java_com_nmi_sazukari_SazukariNative__1szkrDestroyCtx(JNIEnv* env, jclass clazz, int ctxHandle)
{
	szkr_destroy_ctx(g_contexts[ctxHandle].sazukari);
	g_contexts[ctxHandle].sazukari = NULL;
}

void Java_com_nmi_sazukari_SazukariNative__1szkrDestroy(JNIEnv* env, jclass clazz)
{
	int i;
	for (i = 0; i < g_lasthandle; ++i) {
		sn_szkr_ctx_t* sn = &g_contexts[i];
		if (sn->sazukari) {
			szkr_destroy_ctx(sn->sazukari);
		}

		if (sn->resbuf) {
			free(sn->resbuf);
		}
	}
	(*env)->DeleteGlobalRef(env, g_myclass);
}

