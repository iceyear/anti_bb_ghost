cmake_minimum_required(VERSION 3.10)
project("anti_segv" LANGUAGES C)

add_library(anti_segv SHARED
	anti_segv.c
	register_natives_hook.c
	static_jni_probe.c
	artmethod_probe.c
	dexhelper_bypass.c
)
target_link_libraries(anti_segv log)
