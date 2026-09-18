set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CMAKE_SYSTEM_NAME Linux)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_BUILD_TYPE release)

set(VCPKG_ENV_PASSTHROUGH_UNTRACKED
    CEF_STATIC_WORK
    CEF_STATIC_BUILD_TIMEOUT_SECONDS
    CEF_STATIC_PLATFORM_MANIFEST
    CEF_STATIC_PLATFORM_PREFIX
    CEF_STATIC_PLATFORM_SHA256
)

set(X_VCPKG_FORCE_VCPKG_X_LIBRARIES ON)

if(PORT STREQUAL "cef-toolchain-runtime")
    find_program(_cef_runtime_cc NAMES gcc-14 REQUIRED)
    execute_process(COMMAND "${_cef_runtime_cc}" -dumpmachine
        OUTPUT_VARIABLE _cef_machine OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
    if(NOT _cef_machine MATCHES "^x86_64-.*linux.*$")
        message(FATAL_ERROR "CEF atomic runtime requires the native x64 GCC 14 toolchain")
    endif()
    execute_process(COMMAND "${_cef_runtime_cc}" -print-file-name=libatomic.a
        OUTPUT_VARIABLE CEF_STATIC_ATOMIC_FILE OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
    set(CEF_STATIC_RUNTIME_COPYRIGHT "/usr/share/doc/gcc-14-base/copyright")
    if(NOT IS_ABSOLUTE "${CEF_STATIC_ATOMIC_FILE}" OR NOT EXISTS "${CEF_STATIC_ATOMIC_FILE}" OR
       NOT EXISTS "${CEF_STATIC_RUNTIME_COPYRIGHT}")
        message(FATAL_ERROR "Missing static GCC runtime or its redistribution license")
    endif()
    list(APPEND VCPKG_HASH_ADDITIONAL_FILES "${CEF_STATIC_ATOMIC_FILE}" "${CEF_STATIC_RUNTIME_COPYRIGHT}")
endif()
