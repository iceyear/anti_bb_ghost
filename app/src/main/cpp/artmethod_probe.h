#ifndef TANKE_ARTMETHOD_PROBE_H
#define TANKE_ARTMETHOD_PROBE_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

void artmethod_probe_dump(JNIEnv *env, jobject reflected_method, jstring label);

#ifdef __cplusplus
}
#endif

#endif
