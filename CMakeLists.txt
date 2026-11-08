cmake_minimum_required(VERSION 3.20)

project(CrashDetectPlus
  VERSION 1.0.0
  LANGUAGES C CXX
)

option(CDPLUS_BUILD_PLUGIN "Build SA-MP plugin target (plugins/crashdetect)" ON)
option(CDPLUS_BUILD_COMPONENT "Build native open.mp component target (components/crashdetect)" ON)
option(CDPLUS_BUILD_TESTS "Build automated C++20 verification suite" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# SubHook static library (x86 + x64 inline detour engine)
add_library(subhook_static STATIC
  lib/subhook/subhook.c
)
target_include_directories(subhook_static PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/lib/subhook
)
target_compile_definitions(subhook_static PUBLIC SUBHOOK_STATIC)
if(MSVC)
  target_compile_definitions(subhook_static PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Core CrashDetect Plus static engine (shared across SA-MP Plugin, open.mp Component & Tests)
set(CDPLUS_CORE_SOURCES
  src/amx/amx.c
  src/amx/amxaux.c
  src/amx/amxdbg.c
  src/amxcallstack.cpp
  src/amxdebuginfo.cpp
  src/amxopcode.cpp
  src/amxpathfinder.cpp
  src/amxref.cpp
  src/amxstacktrace.cpp
  src/crashdetect_plus.cpp
  src/fileutils.cpp
  src/log.cpp
  src/logprintf.cpp
  src/minidump.cpp
  src/natives.cpp
  src/options.cpp
  src/stacktrace.cpp
  src/stringutils.cpp
  src/webhook.cpp
)

if(WIN32)
  list(APPEND CDPLUS_CORE_SOURCES
    src/os-win32.cpp
    src/stacktrace-win32.cpp
  )
else()
  list(APPEND CDPLUS_CORE_SOURCES
    src/os-unix.cpp
    src/stacktrace-unix.cpp
  )
endif()

add_library(crashdetect_plus_core STATIC ${CDPLUS_CORE_SOURCES})

target_include_directories(crashdetect_plus_core PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_definitions(crashdetect_plus_core PUBLIC
  HAVE_STDINT_H
  sNAMEMAX=63
  PAWN_CELL_SIZE=32
)

if(WIN32)
  target_compile_definitions(crashdetect_plus_core PUBLIC
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
  )
  target_link_libraries(crashdetect_plus_core PUBLIC
    subhook_static
    winhttp
    winmm
  )
else()
  target_compile_definitions(crashdetect_plus_core PUBLIC
    LINUX
    _GNU_SOURCE
  )
  target_link_libraries(crashdetect_plus_core PUBLIC
    subhook_static
    dl
    pthread
  )
endif()

if(MSVC)
  target_compile_options(crashdetect_plus_core PRIVATE /W3 /MP /EHsc /utf-8)
else()
  target_compile_options(crashdetect_plus_core PRIVATE -Wall -Wextra -Wno-unused-parameter -fno-strict-aliasing)
endif()

# ==============================================================================
# Target 1: SA-MP Plugin (plugins/crashdetect.dll | plugins/crashdetect.so)
# ==============================================================================
if(CDPLUS_BUILD_PLUGIN)
  set(CDPLUS_PLUGIN_SOURCES src/plugin.cpp)
  if(WIN32)
    list(APPEND CDPLUS_PLUGIN_SOURCES src/plugin.def src/plugin.rc)
  endif()

  add_library(crashdetect_plugin SHARED ${CDPLUS_PLUGIN_SOURCES})
  target_link_libraries(crashdetect_plugin PRIVATE crashdetect_plus_core)

  set_target_properties(crashdetect_plugin PROPERTIES
    PREFIX ""
    OUTPUT_NAME "crashdetect"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugins"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugins"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugins"
  )
  foreach(CFG Debug Release RelWithDebInfo MinSizeRel)
    string(TOUPPER "${CFG}" CFG_UPPER)
    set_target_properties(crashdetect_plugin PROPERTIES
      ARCHIVE_OUTPUT_DIRECTORY_${CFG_UPPER} "${CMAKE_BINARY_DIR}/plugins"
      LIBRARY_OUTPUT_DIRECTORY_${CFG_UPPER} "${CMAKE_BINARY_DIR}/plugins"
      RUNTIME_OUTPUT_DIRECTORY_${CFG_UPPER} "${CMAKE_BINARY_DIR}/plugins"
    )
  endforeach()

  if(UNIX AND NOT APPLE)
    target_link_options(crashdetect_plugin PRIVATE -Wl,--export-dynamic -static-libgcc -static-libstdc++)
  endif()
endif()

# ==============================================================================
# Target 2: Native open.mp Component (components/crashdetect.dll | .so)
# ==============================================================================
if(CDPLUS_BUILD_COMPONENT AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/lib/open.mp-sdk/CMakeLists.txt")
  # Ensure CMake 4.x compatibility with upstream open.mp-sdk nested submodules (glm, span-lite)
  set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "Minimum CMake policy version for submodules" FORCE)
  add_subdirectory(lib/open.mp-sdk EXCLUDE_FROM_ALL)

  set(CDPLUS_COMPONENT_SOURCES src/component.cpp)
  if(WIN32)
    list(APPEND CDPLUS_COMPONENT_SOURCES src/plugin.rc)
  endif()

  add_library(crashdetect_component SHARED ${CDPLUS_COMPONENT_SOURCES})
  target_link_libraries(crashdetect_component PRIVATE
    crashdetect_plus_core
    OMP-SDK
  )

  if(UNIX AND NOT APPLE)
    target_link_options(crashdetect_component PRIVATE -static-libgcc -static-libstdc++)
  endif()

  set_target_properties(crashdetect_component PROPERTIES
    PREFIX ""
    OUTPUT_NAME "crashdetect"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/components"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/components"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/components"
  )
  foreach(CFG Debug Release RelWithDebInfo MinSizeRel)
    string(TOUPPER "${CFG}" CFG_UPPER)
    set_target_properties(crashdetect_component PROPERTIES
      ARCHIVE_OUTPUT_DIRECTORY_${CFG_UPPER} "${CMAKE_BINARY_DIR}/components"
      LIBRARY_OUTPUT_DIRECTORY_${CFG_UPPER} "${CMAKE_BINARY_DIR}/components"
      RUNTIME_OUTPUT_DIRECTORY_${CFG_UPPER} "${CMAKE_BINARY_DIR}/components"
    )
  endforeach()
endif()

# ==============================================================================
# Target 3: Automated Verification Suite (crashdetect_plus_tests)
# ==============================================================================
if(CDPLUS_BUILD_TESTS)
  enable_testing()
  add_executable(crashdetect_plus_tests
    tests/crashdetect_plus_tests.cpp
  )
  target_link_libraries(crashdetect_plus_tests PRIVATE crashdetect_plus_core)
  if(MSVC)
    target_compile_options(crashdetect_plus_tests PRIVATE /W3 /EHsc /utf-8)
  elseif(UNIX)
    target_link_options(crashdetect_plus_tests PRIVATE -rdynamic)
  endif()
  add_test(NAME CrashDetectPlusSuite COMMAND crashdetect_plus_tests)
endif()
