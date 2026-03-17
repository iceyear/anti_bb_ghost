#ifndef TANKE_REGISTER_NATIVES_HOOK_H
#define TANKE_REGISTER_NATIVES_HOOK_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

void register_natives_hook_install(JNIEnv *env);
void register_natives_hook_set_enabled(int enabled);

#ifdef __cplusplus
}
#endif

#endif
