# Inputs are committed port files so binary ABI lookup sees every semantic pin.
# The encrypted builder may materialize cef-build.json BEFORE invoking vcpkg.
set(_contract_file "${CURRENT_PORT_DIR}/cef-build.json")
if(NOT EXISTS "${_contract_file}")
    file(READ "${CURRENT_PORT_DIR}/cef-defaults.json" _defaults)
    string(JSON _contract ERROR_VARIABLE _error GET "${_defaults}" "${TARGET_TRIPLET}")
    if(_error)
        message(FATAL_ERROR "cef-static supports x64-linux-static-release and x64-windows-static-release only")
    endif()
    set(_contract_file "${CURRENT_BUILDTREES_DIR}/cef-default-resolved.json")
    file(MAKE_DIRECTORY "${CURRENT_BUILDTREES_DIR}")
    file(WRITE "${_contract_file}" "${_contract}\n")
endif()
file(READ "${_contract_file}" _contract)
string(JSON _revision GET "${_contract}" recipe_commit)
string(LENGTH "${_revision}" _revision_length)
if(NOT _revision_length EQUAL 40 OR NOT _revision MATCHES "^[0-9a-f]+$")
    message(FATAL_ERROR "CEF recipe must be an immutable full Git commit")
endif()
# Strict profiles are source-built. Release-import remains an engine-static
# fallback only, so no recipe is patched to promote old release bytes.
vcpkg_from_git(
    OUT_SOURCE_PATH CEF_RECIPE_SOURCE
    URL "https://github.com/dobord/cef.git"
    REF "${_revision}"
)
set(CEF_BUILD_CONTRACT_FILE "${_contract_file}")
include("${CEF_RECIPE_SOURCE}/vcpkg/integration/install.cmake")

# An imported SDK contains its producer's ABI report. It is provenance, not
# the current vcpkg package ABI. The package manager owns the reserved filename.
set(_producer_abi "${CURRENT_PACKAGES_DIR}/share/${PORT}/vcpkg_abi_info.txt")
if(EXISTS "${_producer_abi}")
    file(RENAME "${_producer_abi}"
        "${CURRENT_PACKAGES_DIR}/share/${PORT}/upstream-vcpkg-abi-info.txt")
endif()
