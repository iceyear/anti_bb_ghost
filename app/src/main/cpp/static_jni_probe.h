#ifndef TANKE_STATIC_JNI_PROBE_H
#define TANKE_STATIC_JNI_PROBE_H

#ifdef __cplusplus
extern "C" {
#endif

void static_jni_probe_set_enabled(int enabled);
void static_jni_probe_try_log(void);

#ifdef __cplusplus
}
#endif

#endif
