if(NOT VCPKG_TARGET_IS_LINUX OR VCPKG_CROSSCOMPILING OR
   NOT VCPKG_TARGET_ARCHITECTURE STREQUAL "x64" OR
   NOT VCPKG_LIBRARY_LINKAGE STREQUAL "static" OR
   NOT VCPKG_BUILD_TYPE STREQUAL "release")
    message(FATAL_ERROR "${PORT} requires native Linux x64 static Release")
endif()
vcpkg_from_git(
    OUT_SOURCE_PATH SOURCE_PATH
    URL "https://chromium.googlesource.com/chromiumos/platform/minigbm.git"
    REF 9d21b5cb5896c0cde186b54d430131f9f537104c
    PATCHES no-mock-backend.patch
)
file(COPY "${CURRENT_PORT_DIR}/CMakeLists.txt" "${CURRENT_PORT_DIR}/gbm.pc.in"
     DESTINATION "${SOURCE_PATH}")
vcpkg_cmake_configure(SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS "-DCEF_DEPENDENCY_PREFIX=${CURRENT_INSTALLED_DIR}")
vcpkg_cmake_install()
vcpkg_fixup_pkgconfig()
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
file(INSTALL "${CURRENT_PORT_DIR}/runtime-policy.json" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}")
