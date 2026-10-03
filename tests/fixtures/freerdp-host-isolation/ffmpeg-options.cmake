option(WITH_FFMPEG "Enable FFMPEG for audio/video encoding/decoding" ON)
cmake_dependent_option(WITH_DSP_FFMPEG "Use FFMPEG for audio encoding/decoding" ON "WITH_FFMPEG" OFF)
cmake_dependent_option(WITH_VIDEO_FFMPEG "Use FFMPEG for video encoding/decoding" ON "WITH_FFMPEG" OFF)
cmake_dependent_option(WITH_VAAPI "[experimental] Use FFMPEG VAAPI" OFF "WITH_VIDEO_FFMPEG" OFF)
cmake_dependent_option(
  WITH_VAAPI_H264_ENCODING "[experimental] Use FFMPEG VAAPI hardware H264 encoding" ON "WITH_VIDEO_FFMPEG" OFF
)
cmake_dependent_option(
  WITH_VIDEOTOOLBOX "[experimental] Use FFMPEG VideoToolbox hardware H264 decoding" OFF "WITH_VIDEO_FFMPEG;APPLE" OFF
)
if(WITH_VAAPI_H264_ENCODING)
  include(WarnExperimental)
  warn_experimental("VAAPI H264 encoding" "-DWITH_VAAPI_H264_ENCODING=OFF")

  add_definitions("-DWITH_VAAPI_H264_ENCODING")
endif()

option(WITH_CAIRO "Use CAIRO image library for screen resizing" OFF)
option(WITH_SWSCALE "Use SWScale image library for screen resizing" ON)
