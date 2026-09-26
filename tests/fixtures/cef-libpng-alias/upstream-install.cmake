# Exact excerpts from pnggroup/libpng v1.6.58 CMakeLists.txt.
# Upstream full Git blob: 69042960ffab9473270aa5434f2cf44ba21fb4aa.
# Copyright (c) 2018-2026 Cosmin Truta; SPDX-License-Identifier: libpng-2.0.
# Only the unmodified helper and PNG_STATIC install branch are exercised here.
function(create_symlink DEST_FILE)
  # TODO:
  # Replace this implementation with CMake's built-in create_symlink function,
  # which has been fully functional on all platforms, including Windows, since
  # CMake version 3.13.
  cmake_parse_arguments(_SYM "" "FILE;TARGET" "" ${ARGN})
  if(NOT _SYM_FILE AND NOT _SYM_TARGET)
    message(FATAL_ERROR "create_symlink: Missing arguments: FILE or TARGET")
  endif()
  if(_SYM_FILE AND _SYM_TARGET)
    message(FATAL_ERROR "create_symlink: Mutually-exclusive arguments:"
                        "FILE (${_SYM_FILE}) and TARGET (${_SYM_TARGET})")
  endif()

  if(_SYM_FILE)
    # If we don't need to symlink something that's coming from a build target,
    # we can go ahead and symlink/copy at configure time.
    if(CMAKE_HOST_WIN32 AND NOT CYGWIN)
      execute_process(COMMAND "${CMAKE_COMMAND}"
                              -E copy_if_different
                              "${_SYM_FILE}"
                              "${DEST_FILE}"
                      WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
    else()
      execute_process(COMMAND "${CMAKE_COMMAND}"
                              -E create_symlink
                              "${_SYM_FILE}"
                              "${DEST_FILE}"
                      WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
    endif()
  endif()

  if(_SYM_TARGET)
    # We need to use generator expressions, which can be a bit tricky.
    # For simplicity, make the symlink a POST_BUILD step, and use the TARGET
    # signature of add_custom_command.
    if(CMAKE_HOST_WIN32 AND NOT CYGWIN)
      add_custom_command(TARGET ${_SYM_TARGET}
                         POST_BUILD
                         COMMAND "${CMAKE_COMMAND}"
                                 -E copy_if_different
                                 "$<TARGET_LINKER_FILE_DIR:${_SYM_TARGET}>/$<TARGET_LINKER_FILE_NAME:${_SYM_TARGET}>"
                                 "$<TARGET_LINKER_FILE_DIR:${_SYM_TARGET}>/${DEST_FILE}")
    else()
      add_custom_command(TARGET ${_SYM_TARGET}
                         POST_BUILD
                         COMMAND "${CMAKE_COMMAND}"
                                 -E create_symlink
                                 "$<TARGET_LINKER_FILE_NAME:${_SYM_TARGET}>"
                                 "$<TARGET_LINKER_FILE_DIR:${_SYM_TARGET}>/${DEST_FILE}")
    endif()
  endif()
endfunction()

  if(PNG_STATIC)
    if(NOT WIN32 OR CYGWIN OR MINGW)
      create_symlink(libpng${CMAKE_STATIC_LIBRARY_SUFFIX} TARGET png_static)
      install(FILES "$<TARGET_LINKER_FILE_DIR:png_static>/libpng${CMAKE_STATIC_LIBRARY_SUFFIX}"
              DESTINATION "${CMAKE_INSTALL_LIBDIR}")
    endif()
  endif()
