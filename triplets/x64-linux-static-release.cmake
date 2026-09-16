set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CMAKE_SYSTEM_NAME Linux)
# Match upstream x64-linux: vcpkg BUILD_INFO requires a nonempty CRT linkage.
# This does not change static package libraries into shared libraries.
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_BUILD_TYPE release)
