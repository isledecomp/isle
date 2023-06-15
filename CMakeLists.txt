cmake_minimum_required(VERSION 3.24)

# MSVC runtime library flags are selected by an abstraction
cmake_policy(SET CMP0091 NEW)

project(isledecomp C CXX RC)

if(MSVC)
  set(CMAKE_INSTALL_BINDIR "." CACHE PATH "Install bin directory")
else()
  include(GNUInstallDirs)
endif()

set(ISLE_ACCURACY_DEFAULT FALSE)
# Visual C++ 4.2 ships version 10.20.6166
if(MSVC AND CMAKE_C_COMPILER_VERSION VERSION_LESS "12.0")
  set(ISLE_ACCURACY_DEFAULT TRUE)
endif()

option(ISLE_ACCURACY "Configure CFLAGS for recreating accuarte binaries" ${ISLE_ACCURACY_DEFAULT})

if(MSVC)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()
option(ISLE_WERROR "Treat warnings as errors" OFF)

if(ISLE_WERROR)
  set(CMAKE_COMPILE_WARNING_AS_ERROR ON)
endif()

if(MSVC)
  add_compile_options(/W3)
else()
  add_compile_options(-Wall -Wextra)
endif()

file(GLOB ISLE_SOURCES
  "ISLE/*.c"
  "ISLE/*.cpp"
  "ISLE/*.h"
  "ISLE/res/*.rc"
  "ISLE/res/*.ico"
  "ISLE/res/*.cur"
)
add_executable(isle WIN32
  ${ISLE_SOURCES}
)
target_include_directories(isle PRIVATE .)
target_include_directories(isle PRIVATE ISLE)
target_include_directories(isle PRIVATE LEGO1)
target_link_libraries(isle PRIVATE dsound winmm)
set_property(TARGET isle PROPERTY OUTPUT_NAME ISLE)
set_property(TARGET isle PROPERTY SUFFIX ".EXE")
set_property(TARGET isle PROPERTY CXX_STANDARD "98")
set_property(TARGET isle PROPERTY MSVC_RUNTIME_LIBARY "")
target_compile_options(isle PRIVATE "/ML$<$<CONFIG:Debug>:d>")

if(MSVC)
  add_library(lego01_implib UNKNOWN IMPORTED)
  set_property(TARGET lego01_implib PROPERTY IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/ISLE/ext/lego1.lib")
  target_link_libraries(isle PRIVATE lego01_implib)
else()
  target_link_libraries(isle PRIVATE lego1)
endif()

file(GLOB LEGO1_SOURCES
  "LEGO1/*.c"
  "LEGO1/*.cpp"
  "LEGO1/*.h"
  "LEGO1/*.rc"
  "LEGO1/*.ico"
  "LEGO1/*.cur"
)
add_library(lego1 SHARED
  ${LEGO1_SOURCES}
)
target_link_libraries(lego1 PRIVATE winmm)
set_property(TARGET lego1 PROPERTY OUTPUT_NAME LEGO1)
set_property(TARGET lego1 PROPERTY PREFIX "")
set_property(TARGET lego1 PROPERTY SUFFIX ".DLL")
set_property(TARGET lego1 PROPERTY CXX_STANDARD "98")
set_property(TARGET lego1 PROPERTY DEFINE_SYMBOL "")
set_property(TARGET lego1 PROPERTY PDB_NAME "LEGO1")
set_property(TARGET lego1 PROPERTY MSVC_RUNTIME_LIBARY "")
target_compile_options(lego1 PRIVATE "/MT$<$<CONFIG:Debug>:d>")

if(ISLE_ACCURACY)
  # Flags from isle.mak:
  #   ISLE.EXE:
  #     - Debug: /nologo /MLd /W3 /Gm /GX /Zi /Od /I "LEGO1" /D "WIN32" /D "_DEBUG" /D \
  #              "_WINDOWS" /Fp"$(INTDIR)/ISLE.pch" /YX /Fo"$(INTDIR)/" /Fd"$(INTDIR)/" /c
  #     - Release: /nologo /ML /W3 /GX /Zi /O2 /I "LEGO1" /D "WIN32" /D "NDEBUG" /D\
  #                "_WINDOWS" /Fp"$(INTDIR)/ISLE.pch" /YX /Fo"$(INTDIR)/" /Fd"$(INTDIR)/" /c
  #   LEGO1.DLL:
  #     - Debug: /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS"\
  #              /Fp"$(INTDIR)/LEGO1.pch" /YX /Fo"$(INTDIR)/" /Fd"$(INTDIR)/" /c
  #     - Release: /nologo /MT /W3 /GX /Zi /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS"\
  #                /Fp"$(INTDIR)/LEGO1.pch" /YX /Fo"$(INTDIR)/" /Fd"$(INTDIR)/" /c

  # This is a fancy way of saying:
  # - /MT for shared libraries in Release configuration
  # - /MTd for shared libraries in Debug configuration
  # - /ML for executables in Release configuration
  # - /MLd for executables in Debug configuration
  #set(stl_library "$<$<STREQUAL:$<TARGET_TYPE>,SHARED_LIBRARY>:/MT>$<$<STREQUAL:$<TARGET_TYPE>,EXECUTABLE>:/ML>$<$<CONFIG:Debug>:d>")

  #set_property(TARGET isle lego1 PROPERTY MSVC_RUNTIME_LIBRARY "")
  set(CMAKE_C_FLAGS "/GX /Zi /DWIN32 /D_WINDOWS")
  set(CMAKE_CXX_FLAGS "/GX /Zi /DWIN32 /D_WINDOWS")

  set(CMAKE_C_FLAGS_RELEASE "/O2")
  set(CMAKE_CXX_FLAGS_RELEASE "/O2")
  set(CMAKE_C_FLAGS_DEBUG "/Gm /Od /D_DEBUG")
  set(CMAKE_CXX_FLAGS_DEBUG "/Gm /Od /D_DEBUG")

  set(CMAKE_SHARED_LINKER_FLAGS "/machine:I386 /subsystem:windows")
  set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "/debug /incremental:no")  # /debug creates a pdb
  set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "/debug /incremental:yes")

  set(CMAKE_EXE_LINKER_FLAGS "/machine:I386 /subsystem:windows")
  set(CMAKE_EXE_LINKER_FLAGS_RELEASE "/debug /incremental:no")  # /debug creates a pdb
  set(CMAKE_EXE_LINKER_FLAGS_DEBUG "/debug /incremental:yes")

  set(CMAKE_C_STANDARD_LIBRARIES "kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib")
  string(APPEND CMAKE_C_STANDARD_LIBRARIES " advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib")
  string(APPEND CMAKE_C_STANDARD_LIBRARIES " odbccp32.lib")
  set(CMAKE_CXX_STANDARD_LIBRARIES ${CMAKE_C_STANDARD_LIBRARIES})
endif()


message(STATUS "Compiler ID:                        ${CMAKE_C_COMPILER_ID}")
message(STATUS "Compiler version:                   ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "CMAKE_BUILD_TYPE:                   ${CMAKE_BUILD_TYPE}")
message(STATUS "")
message(STATUS "CMAKE_C_FLAGS:                      ${CMAKE_C_FLAGS}")
message(STATUS "CMAKE_C_FLAGS_DEBUG:                ${CMAKE_C_FLAGS_DEBUG}")
message(STATUS "CMAKE_C_FLAGS_RELEASE:              ${CMAKE_C_FLAGS_RELEASE}")
message(STATUS "")
message(STATUS "CMAKE_CXX_FLAGS:                    ${CMAKE_CXX_FLAGS}")
message(STATUS "CMAKE_CXX_FLAGS_DEBUG:              ${CMAKE_CXX_FLAGS_DEBUG}")
message(STATUS "CMAKE_CXX_FLAGS_RELEASE:            ${CMAKE_CXX_FLAGS_RELEASE}")
message(STATUS "")
message(STATUS "CMAKE_EXE_LINKER_FLAGS:             ${CMAKE_EXE_LINKER_FLAGS}")
message(STATUS "CMAKE_EXE_LINKER_FLAGS_RELEASE:     ${CMAKE_EXE_LINKER_FLAGS_RELEASE}")
message(STATUS "CMAKE_EXE_LINKER_FLAGS_DEBUG:       ${CMAKE_EXE_LINKER_FLAGS_DEBUG}")
message(STATUS "")
message(STATUS "CMAKE_SHARED_LINKER_FLAGS:          ${CMAKE_SHARED_LINKER_FLAGS}")
message(STATUS "CMAKE_SHARED_LINKER_FLAGS_RELEASE:  ${CMAKE_SHARED_LINKER_FLAGS_RELEASE}")
message(STATUS "CMAKE_SHARED_LINKER_FLAGS_DEBUG:    ${CMAKE_SHARED_LINKER_FLAGS_DEBUG}")
message(STATUS "")
message(STATUS "CMAKE_C_STANDARD_LIBRARIES: ${CMAKE_C_STANDARD_LIBRARIES}")
message(STATUS "")

get_property(isle_options TARGET isle PROPERTY COMPILE_OPTIONS)
string(JOIN " " isle_options ${isle_options})
message(STATUS "ISLE flags:                   ${isle_options}")

get_property(lego1_options TARGET lego1 PROPERTY COMPILE_OPTIONS)
string(JOIN " " lego1_options ${lego1_options})
message(STATUS "LEGO1 flags:                  ${lego1_options}")
message(STATUS "")

install(PROGRAMS "$<TARGET_FILE:isle>" "$<TARGET_FILE:lego1>"
  DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
if(MSVC)
  install(FILES install "$<TARGET_PDB_FILE:isle>" "$<TARGET_PDB_FILE:lego1>"
    DESTINATION "${CMAKE_INSTALL_BINDIR}"
    OPTIONAL
  )
endif()
