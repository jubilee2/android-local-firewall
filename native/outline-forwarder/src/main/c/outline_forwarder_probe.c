#include <jni.h>

#define PROBE_RESULT "outline-sdk@6f5902f532d67ffde0c02f9ec19bb176d859f173;lwip2transport;jni-v1"

JNIEXPORT jstring JNICALL
Java_com_localfirewall_app_network_outline_JniOutlineForwarderProbe_nativeProbe(
        JNIEnv *env,
        jobject instance) {
    (void) instance;
    return (*env)->NewStringUTF(env, PROBE_RESULT);
}
