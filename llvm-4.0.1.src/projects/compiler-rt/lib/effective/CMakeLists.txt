add_compiler_rt_component(effective)

set(EFFECTIVE_SOURCES
  effective.c
  effective_data.c
  effective_malloc.c
  effective_log.c
  lowfat.c)

include_directories(..)

set(EFFECTIVE_CFLAGS -std=gnu99 -m64 -I. -O2 -msse4.2 -msse4.1 -mcmodel=large -DLOWFAT_LINUX -Wno-gnu-empty-initializer -Wno-gnu-flexible-array-initializer -Wno-zero-length-array -DLOWFAT_LEGACY=1)

add_compiler_rt_runtime(clang_rt.effective
        STATIC
        ARCHS x86_64 
        SOURCES ${EFFECTIVE_SOURCES}
        CFLAGS ${EFFECTIVE_CFLAGS}
        PARENT_TARGET effective)

add_sanitizer_rt_symbols(clang_rt.effective)

add_dependencies(compiler-rt effective)

