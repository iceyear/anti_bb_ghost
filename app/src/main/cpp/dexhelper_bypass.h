#pragma once

/* Hook pthread_create inside libDexHelper.so via GOT patch.
 *
 * When the bypass is enabled:
 *   - A background thread polls /proc/self/maps until libDexHelper.so appears.
 *   - On first detection, it patches libDexHelper.so's GOT entry for
 *     pthread_create to point to our hook.
 *   - Our hook replaces the start_routine with a NOP function whenever the
 *     routine lives inside libDexHelper.so, preventing the detection thread
 *     from executing any code.
 *
 * This is the native equivalent of the Frida hook_clone + nop_64 technique.
 */

void dexhelper_bypass_set_enabled(int enabled);
void dexhelper_bypass_try_patch_now(void);
