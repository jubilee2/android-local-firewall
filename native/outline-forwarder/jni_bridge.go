//go:build android && cgo

package main

/*
#include <jni.h>
#include <stdlib.h>
#include <stdint.h>

static JavaVM* g_jvm = NULL;

static void set_jvm(JavaVM* vm) {
    g_jvm = vm;
}

static int attach_env(JNIEnv** out_env, int* out_needs_detach) {
    *out_env = NULL;
    *out_needs_detach = 0;
    if (g_jvm == NULL) {
        return -1;
    }
    jint status = (*g_jvm)->GetEnv(g_jvm, (void**)out_env, JNI_VERSION_1_6);
    if (status == JNI_OK) {
        return 0;
    }
    if (status == JNI_EDETACHED) {
        if ((*g_jvm)->AttachCurrentThread(g_jvm, out_env, NULL) != JNI_OK) {
            return -1;
        }
        *out_needs_detach = 1;
        return 0;
    }
    return -1;
}

static void detach_env_if_needed(int needs_detach) {
    if (needs_detach && g_jvm != NULL) {
        (*g_jvm)->DetachCurrentThread(g_jvm);
    }
}

static jobject new_global_ref(JNIEnv* env, jobject obj) {
    return (*env)->NewGlobalRef(env, obj);
}

static int is_null_jobject(jobject obj) {
    return obj == NULL ? 1 : 0;
}

static void delete_global_ref(jobject global_ref) {
    if (global_ref == NULL) return;
    JNIEnv* env = NULL;
    int needs_detach = 0;
    if (attach_env(&env, &needs_detach) == 0) {
        (*env)->DeleteGlobalRef(env, global_ref);
        detach_env_if_needed(needs_detach);
    }
}

static jmethodID lookup_method(JNIEnv* env, jobject target, const char* name, const char* sig) {
    jclass cls = (*env)->GetObjectClass(env, target);
    if (cls == NULL) return NULL;
    jmethodID mid = (*env)->GetMethodID(env, cls, name, sig);
    (*env)->DeleteLocalRef(env, cls);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        return NULL;
    }
    return mid;
}

static void throw_illegal_state(JNIEnv* env, const char* message) {
    jclass exCls = (*env)->FindClass(env, "java/lang/IllegalStateException");
    if (exCls != NULL) {
        (*env)->ThrowNew(env, exCls, message);
        (*env)->DeleteLocalRef(env, exCls);
    }
}

static jboolean call_admit_packet(
    jobject callback_ref,
    jmethodID admit_mid,
    jint ip_version,
    jint protocol,
    const void* src_bytes,
    jsize src_len,
    jint src_port,
    const void* dst_bytes,
    jsize dst_len,
    jint dst_port,
    jint identification,
    jint fragment_offset,
    jboolean more_fragments
) {
    JNIEnv* env = NULL;
    int needs_detach = 0;
    if (attach_env(&env, &needs_detach) != 0) {
        return JNI_FALSE;
    }

    jbyteArray src_arr = (*env)->NewByteArray(env, src_len);
    jbyteArray dst_arr = (*env)->NewByteArray(env, dst_len);
    if (src_arr == NULL || dst_arr == NULL || (*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        if (src_arr != NULL) (*env)->DeleteLocalRef(env, src_arr);
        if (dst_arr != NULL) (*env)->DeleteLocalRef(env, dst_arr);
        detach_env_if_needed(needs_detach);
        return JNI_FALSE;
    }

    (*env)->SetByteArrayRegion(env, src_arr, 0, src_len, (const jbyte*)src_bytes);
    (*env)->SetByteArrayRegion(env, dst_arr, 0, dst_len, (const jbyte*)dst_bytes);

    jboolean admitted = (*env)->CallBooleanMethod(
        env,
        callback_ref,
        admit_mid,
        ip_version,
        protocol,
        src_arr,
        src_port,
        dst_arr,
        dst_port,
        identification,
        fragment_offset,
        more_fragments
    );
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        admitted = JNI_FALSE;
    }

    (*env)->DeleteLocalRef(env, src_arr);
    (*env)->DeleteLocalRef(env, dst_arr);
    detach_env_if_needed(needs_detach);
    return admitted;
}

static jboolean call_protect_socket(jobject callback_ref, jmethodID protect_mid, jint fd) {
    JNIEnv* env = NULL;
    int needs_detach = 0;
    if (attach_env(&env, &needs_detach) != 0) {
        return JNI_FALSE;
    }

    jboolean protected_ok = (*env)->CallBooleanMethod(env, callback_ref, protect_mid, fd);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        protected_ok = JNI_FALSE;
    }

    detach_env_if_needed(needs_detach);
    return protected_ok;
}

static void call_on_fatal_error(jobject callback_ref, jmethodID fatal_mid, const char* reason) {
    JNIEnv* env = NULL;
    int needs_detach = 0;
    if (attach_env(&env, &needs_detach) != 0) {
        return;
    }

    jstring jreason = (*env)->NewStringUTF(env, reason);
    if (jreason != NULL && !(*env)->ExceptionCheck(env)) {
        (*env)->CallVoidMethod(env, callback_ref, fatal_mid, jreason);
    }
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
    }
    if (jreason != NULL) {
        (*env)->DeleteLocalRef(env, jreason);
    }

    detach_env_if_needed(needs_detach);
}

static jstring JNIEnv_NewStringUTF_helper(JNIEnv* env, const char* utf) {
    return (*env)->NewStringUTF(env, utf);
}
*/
import "C"

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

var (
	handlesMu    sync.Mutex
	handles      = make(map[int64]*Forwarder)
	nextHandleID atomic.Int64
)

type jniCallbacks struct {
	globalRef  C.jobject
	admitMID   C.jmethodID
	protectMID C.jmethodID
	fatalMID   C.jmethodID
	released   atomic.Bool
}

func (j *jniCallbacks) AdmitPacket(hdr ParsedPacketHeader) bool {
	if j.released.Load() {
		return false
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var srcSlice, dstSlice []byte
	if hdr.IPVersion == 4 {
		s4 := hdr.SourceIP.As4()
		d4 := hdr.DestinationIP.As4()
		srcSlice = s4[:]
		dstSlice = d4[:]
	} else {
		s16 := hdr.SourceIP.As16()
		d16 := hdr.DestinationIP.As16()
		srcSlice = s16[:]
		dstSlice = d16[:]
	}

	moreFrags := C.jboolean(C.JNI_FALSE)
	if hdr.MoreFragments {
		moreFrags = C.jboolean(C.JNI_TRUE)
	}

	res := C.call_admit_packet(
		j.globalRef,
		j.admitMID,
		C.jint(hdr.IPVersion),
		C.jint(hdr.Protocol),
		unsafe.Pointer(&srcSlice[0]),
		C.jsize(len(srcSlice)),
		C.jint(hdr.SourcePort),
		unsafe.Pointer(&dstSlice[0]),
		C.jsize(len(dstSlice)),
		C.jint(hdr.DestinationPort),
		C.jint(hdr.Identification),
		C.jint(hdr.FragmentOffset),
		moreFrags,
	)
	return res == C.JNI_TRUE
}

func (j *jniCallbacks) ProtectSocket(fd int) bool {
	if j.released.Load() {
		return false
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	return C.call_protect_socket(j.globalRef, j.protectMID, C.jint(fd)) == C.JNI_TRUE
}

func (j *jniCallbacks) OnFatalError(reason string) {
	if j.released.Load() {
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	creason := C.CString(reason)
	defer C.free(unsafe.Pointer(creason))
	C.call_on_fatal_error(j.globalRef, j.fatalMID, creason)
}

func (j *jniCallbacks) release() {
	if j.released.CompareAndSwap(false, true) {
		C.delete_global_ref(j.globalRef)
	}
}

//export JNI_OnLoad
func JNI_OnLoad(vm *C.JavaVM, _ unsafe.Pointer) C.jint {
	C.set_jvm(vm)
	return C.JNI_VERSION_1_6
}

//export Java_com_localfirewall_app_network_outline_OutlineNativeBridge_nativeMetadata
func Java_com_localfirewall_app_network_outline_OutlineNativeBridge_nativeMetadata(env *C.JNIEnv, _ C.jclass) C.jstring {
	meta := BridgeMetadataJSON()
	cmeta := C.CString(meta)
	defer C.free(unsafe.Pointer(cmeta))
	return C.JNIEnv_NewStringUTF_helper(env, cmeta)
}

//export Java_com_localfirewall_app_network_outline_OutlineNativeBridge_nativeStart
func Java_com_localfirewall_app_network_outline_OutlineNativeBridge_nativeStart(
	env *C.JNIEnv,
	_ C.jclass,
	tunFd C.jint,
	callbacksObj C.jobject,
	maxTCP C.jint,
	maxUDP C.jint,
	udpIdleMillis C.jint,
) C.jlong {
	if C.is_null_jobject(callbacksObj) != 0 {
		throwIllegalState(env, "callbacks must not be null")
		return 0
	}

	cAdmitName := C.CString("admitPacket")
	cAdmitSig := C.CString("(II[BI[BIIIIZ)Z")
	cProtectName := C.CString("protectSocket")
	cProtectSig := C.CString("(I)Z")
	cFatalName := C.CString("onFatalError")
	cFatalSig := C.CString("(Ljava/lang/String;)V")
	defer func() {
		C.free(unsafe.Pointer(cAdmitName))
		C.free(unsafe.Pointer(cAdmitSig))
		C.free(unsafe.Pointer(cProtectName))
		C.free(unsafe.Pointer(cProtectSig))
		C.free(unsafe.Pointer(cFatalName))
		C.free(unsafe.Pointer(cFatalSig))
	}()

	admitMID := C.lookup_method(env, callbacksObj, cAdmitName, cAdmitSig)
	protectMID := C.lookup_method(env, callbacksObj, cProtectName, cProtectSig)
	fatalMID := C.lookup_method(env, callbacksObj, cFatalName, cFatalSig)
	if admitMID == nil || protectMID == nil || fatalMID == nil {
		throwIllegalState(env, "missing required NativeForwarderCallbacks JNI method signature")
		return 0
	}

	globalRef := C.new_global_ref(env, callbacksObj)
	if C.is_null_jobject(globalRef) != 0 {
		throwIllegalState(env, "failed to allocate JNI global reference")
		return 0
	}

	cb := &jniCallbacks{
		globalRef:  globalRef,
		admitMID:   admitMID,
		protectMID: protectMID,
		fatalMID:   fatalMID,
	}

	cfg := Config{
		MaxTCPStreams:      int(maxTCP),
		MaxUDPAssociations: int(maxUDP),
	}
	if udpIdleMillis > 0 {
		cfg.UDPIdleTimeout = time.Duration(udpIdleMillis) * time.Millisecond
	}

	fwd, err := StartForwarder(int(tunFd), cb, cfg)
	if err != nil {
		cb.release()
		throwIllegalState(env, err.Error())
		return 0
	}

	fwd.stateMu.Lock()
	fwd.onCloseRelease = cb.release
	fwd.stateMu.Unlock()

	handleID := nextHandleID.Add(1)
	handlesMu.Lock()
	handles[handleID] = fwd
	handlesMu.Unlock()
	return C.jlong(handleID)
}

//export Java_com_localfirewall_app_network_outline_OutlineNativeBridge_nativeStop
func Java_com_localfirewall_app_network_outline_OutlineNativeBridge_nativeStop(
	env *C.JNIEnv,
	_ C.jclass,
	handle C.jlong,
) {
	id := int64(handle)
	handlesMu.Lock()
	fwd, exists := handles[id]
	handlesMu.Unlock()
	if !exists || fwd == nil {
		return
	}

	if err := fwd.Stop(); err != nil {
		throwIllegalState(env, err.Error())
		return
	}

	handlesMu.Lock()
	delete(handles, id)
	handlesMu.Unlock()
}

func throwIllegalState(env *C.JNIEnv, msg string) {
	cmsg := C.CString(msg)
	defer C.free(unsafe.Pointer(cmsg))
	C.throw_illegal_state(env, cmsg)
}
