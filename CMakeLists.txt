cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

# MSVC runtime library flags are selected by an abstraction
cmake_policy(SET CMP0091 NEW)

project(isle CXX)

# MSVC < 12 writes one compiler PDB per TARGET (/Fd<target>.dir/) and cannot
# have two cl processes writing it at once ("fatal error C1033: cannot open
# program database"), which is why the build has been -j1 for MSVC 4.20.
# One PDB per OBJECT removes the shared resource. /Fo and /Fd are codegen- and
# emission-order-inert, and the final images are identical apart from the
# linker's timestamps (which vary between any two links anyway).
option(ISLE_PER_OBJECT_PDB "Emit one compiler PDB per object file so MSVC < 12 can compile in parallel" ON)
if(ISLE_PER_OBJECT_PDB AND CMAKE_CXX_COMPILE_OBJECT MATCHES "/Fd<TARGET_COMPILE_PDB>")
  string(REPLACE "/Fd<TARGET_COMPILE_PDB>" "/Fd<OBJECT>.pdb"
         CMAKE_CXX_COMPILE_OBJECT "${CMAKE_CXX_COMPILE_OBJECT}")
  string(REPLACE "/Fd<TARGET_COMPILE_PDB>" "/Fd<OBJECT>.pdb"
         CMAKE_C_COMPILE_OBJECT "${CMAKE_C_COMPILE_OBJECT}")
  message(STATUS "Per-object compiler PDBs enabled: parallel builds are safe")
endif()

include(CheckCXXSourceCompiles)
include(CMakeDependentOption)
include(CMakePushCheckState)
include("${CMAKE_CURRENT_LIST_DIR}/cmake/reccmp.cmake")

set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)
option(ENABLE_CLANG_TIDY "Enable clang-tidy")
if (ENABLE_CLANG_TIDY)
  find_program(CLANG_TIDY_BIN NAMES "clang-tidy")
  set(CMAKE_C_CLANG_TIDY "${CLANG_TIDY_BIN}")
  set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_BIN}")
endif()

math(EXPR bits "8 * ${CMAKE_SIZEOF_VOID_P}")
message(STATUS "Building ${bits}-bit LEGO Island")
if (NOT bits EQUAL 32)
  message(WARNING "Only 32-bit executables are supported")
endif()

set(MSVC_FOR_DECOMP FALSE)
if (MSVC)
  # Visual C++ 4.2 -> cl version 10.2.0
  if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS "11.0")
    set(MSVC_FOR_DECOMP TRUE)
  endif()
endif()

function(add_cxx_warning WARNING)
  if(ISLE_WERROR)
    set(compiler_option "-Werror=${WARNING}")
  else()
    set(compiler_option "-W${WARNING}")
  endif()
  string(MAKE_C_IDENTIFIER "COMPILER_SUPPORTS${compiler_option}" varname)

  cmake_push_check_state(RESET)
  set(CMAKE_REQUIRED_FLAGS "${compiler_option} ")
  if(MSVC)
    string(APPEND CMAKE_REQUIRED_FLAGS "/WX")
  else()
    string(APPEND CMAKE_REQUIRED_FLAGS "-Werror")
  endif()
  check_cxx_source_compiles("int main() { return 0; }" ${varname})
  cmake_pop_check_state()

  if(${varname})
    add_compile_options(${compiler_option})
  endif()
endfunction()

message(STATUS "MSVC for decompilation: ${MSVC_FOR_DECOMP}")

option(ISLE_WERROR "Treat warnings as errors" OFF)
option(ISLE_BUILD_APP "Build ISLE.EXE application" ON)
cmake_dependent_option(ISLE_BUILD_CONFIG "Build CONFIG.EXE application" ON "NOT MINGW" OFF)
option(ISLE_USE_SMARTHEAP "Build LEGO1.DLL with SmartHeap" ${MSVC_FOR_DECOMP})
option(ISLE_USE_DX5 "Build with internal DirectX 5 SDK" ON)
option(ISLE_DECOMP_ASSERT "Assert struct size" ${MSVC_FOR_DECOMP})
cmake_dependent_option(ISLE_USE_DX5_LIBS "Build with internal DirectX 5 SDK Libraries" ON ISLE_USE_DX5 OFF)
option(ISLE_BUILD_LEGO1 "Build LEGO1.DLL library" ON)
option(ISLE_BUILD_BETA10 "Build BETA10.DLL library" OFF)
option(ISLE_INCLUDE_ENTROPY "Build with entropy.h" OFF)
option(ISLE_ENTROPY_FILENAME "Entropy header filename" "entropy.h")
option(ISLE_BYTE_IDENTICAL "Build for byte-identity with the retail binaries: emit no debug information, so the image carries no DEBUG data directory (the originals have none). Produces no PDB, so reccmp cannot be used on such a build - configure it in a SEPARATE build directory and keep the default one for reccmp work." OFF)

if(NOT (ISLE_BUILD_LEGO1 OR ISLE_BUILD_BETA10))
  message(FATAL_ERROR "ISLE_BUILD_LEGO1 AND ISLE_BUILD_BETA10 cannot be both disabled")
endif()

add_cxx_warning(parentheses)

add_library(DirectX5::DirectX5 INTERFACE IMPORTED)
target_include_directories(DirectX5::DirectX5 INTERFACE "${PROJECT_SOURCE_DIR}/3rdparty/dx5/inc")
if(ISLE_USE_DX5_LIBS)
  target_link_directories(DirectX5::DirectX5 INTERFACE "${PROJECT_SOURCE_DIR}/3rdparty/dx5/lib")
endif()

add_library(Smacker::Smacker STATIC IMPORTED)
set_property(TARGET Smacker::Smacker PROPERTY IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/3rdparty/smacker/smackw32.lib")
set_property(TARGET Smacker::Smacker PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/3rdparty/smacker")

add_library(Vec::Vec INTERFACE IMPORTED)
target_include_directories(Vec::Vec INTERFACE "${PROJECT_SOURCE_DIR}/3rdparty/vec")

add_library(SmartHeap::SmartHeap STATIC IMPORTED)
set_property(TARGET SmartHeap::SmartHeap PROPERTY IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/3rdparty/smartheap/SHLW32MT.LIB")
set_property(TARGET SmartHeap::SmartHeap PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/3rdparty/smartheap")
set_property(TARGET SmartHeap::SmartHeap PROPERTY INTERFACE_COMPILE_OPTIONS "/FI${PROJECT_SOURCE_DIR}/3rdparty/smartheap/SMRTHEAP.HPP")

function(add_lego_libraries NAME)
  cmake_parse_arguments(ARG "" "SUFFIX;OUT_TARGETS;DLL_OUTPUT_NAME;DLL_PREFIX;DLL_SUFFIX" "LINK_LIBRARIES" ${ARGN})

  set(list_targets )

  set(SUFFIX "${ARG_SUFFIX}")

  add_library(tglrl${ARG_SUFFIX} STATIC
    LEGO1/tgl/d3drm/tglrl40.cpp
  )
  list(APPEND list_targets tglrl${ARG_SUFFIX})
  set_property(TARGET tglrl${ARG_SUFFIX} PROPERTY ARCHIVE_OUTPUT_NAME "tglrl40$<$<CONFIG:Debug>:d>${ARG_SUFFIX}")
  target_include_directories(tglrl${ARG_SUFFIX} PRIVATE "${PROJECT_SOURCE_DIR}/LEGO1" "${PROJECT_SOURCE_DIR}/util")
  target_link_libraries(tglrl${ARG_SUFFIX} PRIVATE d3drm)

  add_library(realtime${ARG_SUFFIX} STATIC
    LEGO1/realtime/orientableroi.cpp
    LEGO1/realtime/realtimeview.cpp
  )
  list(APPEND list_targets realtime${ARG_SUFFIX})
  set_property(TARGET realtime${ARG_SUFFIX} PROPERTY ARCHIVE_OUTPUT_NAME "realtime$<$<CONFIG:Debug>:d>${ARG_SUFFIX}")
  target_include_directories(realtime${ARG_SUFFIX} PRIVATE "${PROJECT_SOURCE_DIR}/LEGO1" "${PROJECT_SOURCE_DIR}/util")
  target_link_libraries(realtime${ARG_SUFFIX} PRIVATE Vec::Vec)

  add_library(viewmanager${ARG_SUFFIX} STATIC
    LEGO1/viewmanager/viewlod.cpp
    LEGO1/viewmanager/viewmanager.cpp
    LEGO1/viewmanager/viewlodlist.cpp
  )
  list(APPEND list_targets viewmanager${ARG_SUFFIX})
  set_property(TARGET viewmanager${ARG_SUFFIX} PROPERTY ARCHIVE_OUTPUT_NAME "viewmanager$<$<CONFIG:Debug>:d>${ARG_SUFFIX}")
  target_include_directories(viewmanager${ARG_SUFFIX} PRIVATE "${PROJECT_SOURCE_DIR}/LEGO1" "${PROJECT_SOURCE_DIR}/util")
  target_link_libraries(viewmanager${ARG_SUFFIX} PRIVATE Vec::Vec)

  add_library(mxdirectx${ARG_SUFFIX} STATIC
    LEGO1/mxdirectx/mxdirect3d.cpp
    LEGO1/mxdirectx/mxdirectxinfo.cpp
    LEGO1/mxdirectx/legodxinfo.cpp
    LEGO1/mxdirectx/mxdirectdraw.cpp
  )
  list(APPEND list_targets mxdirectx${ARG_SUFFIX})
  set_property(TARGET mxdirectx${ARG_SUFFIX} PROPERTY ARCHIVE_OUTPUT_NAME "MxDirectX$<$<CONFIG:Debug>:d>${ARG_SUFFIX}")
  target_include_directories(mxdirectx${ARG_SUFFIX} PRIVATE "${PROJECT_SOURCE_DIR}/LEGO1" "${PROJECT_SOURCE_DIR}/util")
  target_link_libraries(mxdirectx${ARG_SUFFIX} PRIVATE ddraw)

  # `viewroi.cpp` is a member of THIS archive, not of viewmanager: retail places
  # its block strictly between legoroi's and legolod's, and LINK's per-library
  # scan is contiguous in load order, so ViewROI cannot be pulled from a library
  # scanned before roi. Measured: module-order inversions 572 -> 496, functions
  # at retail's exact VA 927 -> 929, reccmp unchanged (4737, zero movers).
  add_library(roi${ARG_SUFFIX} STATIC
    LEGO1/lego/sources/roi/legoroi.cpp
    LEGO1/viewmanager/viewroi.cpp
    LEGO1/lego/sources/roi/legolod.cpp
  )
  list(APPEND list_targets roi${ARG_SUFFIX})
  set_property(TARGET roi${ARG_SUFFIX} PROPERTY ARCHIVE_OUTPUT_NAME "roi$<$<CONFIG:Debug>:d>${ARG_SUFFIX}")
  target_include_directories(roi${ARG_SUFFIX} PRIVATE "${PROJECT_SOURCE_DIR}/LEGO1/omni/include" "${PROJECT_SOURCE_DIR}/LEGO1" "${PROJECT_SOURCE_DIR}/LEGO1/lego/sources" "${PROJECT_SOURCE_DIR}/util")
  target_link_libraries(roi${ARG_SUFFIX} PRIVATE viewmanager${ARG_SUFFIX} Vec::Vec)

  add_library(geom${ARG_SUFFIX} STATIC
    LEGO1/lego/sources/geom/legoweedge.cpp
    LEGO1/lego/sources/geom/legowegedge.cpp
  )
  list(APPEND list_targets geom${ARG_SUFFIX})
  set_property(TARGET geom${ARG_SUFFIX} PROPERTY ARCHIVE_OUTPUT_NAME "geom$<$<CONFIG:Debug>:d>${ARG_SUFFIX}")
  target_include_directories(geom${ARG_SUFFIX} PRIVATE "${PROJECT_SOURCE_DIR}/LEGO1/omni/include" "${PROJECT_SOURCE_DIR}/LEGO1" "${PROJECT_SOURCE_DIR}/LEGO1/lego/sources" "${PROJECT_SOURCE_DIR}/util")
  target_link_libraries(geom${ARG_SUFFIX} PRIVATE)

  add_library(shape${ARG_SUFFIX} STATIC
    LEGO1/lego/sources/shape/legobox.cpp
    LEGO1/lego/sources/shape/legosphere.cpp
    LEGO1/lego/sources/shape/legovertex.cpp
    LEGO1/lego/sources/shape/legomesh.cpp
    LEGO1/lego/sources/shape/legocolor.cpp
  )
  list(APPEND list_targets shape${ARG_SUFFIX})
  set_property(TARGET shape${ARG_SUFFIX} PROPERTY ARCHIVE_OUTPUT_NAME "shape$<$<CONFIG:Debug>:d>${ARG_SUFFIX}")
  target_include_directories(shape${ARG_SUFFIX} PRIVATE "${PROJECT_SOURCE_DIR}/LEGO1/omni/include" "${PROJECT_SOURCE_DIR}/LEGO1" "${PROJECT_SOURCE_DIR}/LEGO1/lego/sources" "${PROJECT_SOURCE_DIR}/util")
  target_link_libraries(shape${ARG_SUFFIX} PRIVATE)

  add_library(anim${ARG_SUFFIX} STATIC
    LEGO1/lego/sources/anim/legoanim.cpp
  )
  list(APPEND list_targets anim${ARG_SUFFIX})
  set_property(TARGET anim${ARG_SUFFIX} PROPERTY ARCHIVE_OUTPUT_NAME "anim$<$<CONFIG:Debug>:d>${ARG_SUFFIX}")
  target_include_directories(anim${ARG_SUFFIX} PRIVATE "${PROJECT_SOURCE_DIR}/LEGO1/omni/include" "${PROJECT_SOURCE_DIR}/LEGO1" "${PROJECT_SOURCE_DIR}/LEGO1/lego/sources" "${PROJECT_SOURCE_DIR}/util")

  add_library(misc${ARG_SUFFIX} STATIC
    LEGO1/lego/sources/misc/legotexture.cpp
    LEGO1/lego/sources/misc/legospline.cpp
    LEGO1/lego/sources/misc/legostorage.cpp
    LEGO1/lego/sources/misc/legoimage.cpp
    LEGO1/lego/sources/misc/legocontainer.cpp
    LEGO1/lego/sources/misc/legotree.cpp
  )
  list(APPEND list_targets misc${ARG_SUFFIX})
  set_property(TARGET misc${ARG_SUFFIX} PROPERTY ARCHIVE_OUTPUT_NAME "misc$<$<CONFIG:Debug>:d>${ARG_SUFFIX}")
  target_include_directories(misc${ARG_SUFFIX} PRIVATE "${PROJECT_SOURCE_DIR}/LEGO1/omni/include" "${PROJECT_SOURCE_DIR}/LEGO1" "${PROJECT_SOURCE_DIR}/LEGO1/lego/sources" "${PROJECT_SOURCE_DIR}/util")
  target_link_libraries(misc${ARG_SUFFIX} PRIVATE)

  add_library(3dmanager${ARG_SUFFIX} STATIC
    LEGO1/lego/sources/3dmanager/lego3dview.cpp
    LEGO1/lego/sources/3dmanager/lego3dmanager.cpp
    LEGO1/lego/sources/3dmanager/legoview1.cpp
    LEGO1/lego/sources/3dmanager/tglsurface.cpp
  )
  list(APPEND list_targets 3dmanager${ARG_SUFFIX})
  set_property(TARGET 3dmanager${ARG_SUFFIX} PROPERTY ARCHIVE_OUTPUT_NAME "3dmanager$<$<CONFIG:Debug>:d>${ARG_SUFFIX}")
  target_include_directories(3dmanager${ARG_SUFFIX} PRIVATE "${PROJECT_SOURCE_DIR}/LEGO1" "${PROJECT_SOURCE_DIR}/util")
  target_link_libraries(3dmanager${ARG_SUFFIX} PRIVATE Vec::Vec)

  add_library(omni${ARG_SUFFIX} STATIC
    LEGO1/omni/src/notify/mxnotificationmanager.cpp
    LEGO1/omni/src/common/mxdebug.cpp
    LEGO1/omni/src/common/mxmisc.cpp
    LEGO1/omni/src/common/mxatom.cpp
    LEGO1/omni/src/action/mxdsaction.cpp
    LEGO1/omni/src/common/mxtimer.cpp
    LEGO1/omni/src/common/mxcore.cpp
    LEGO1/omni/src/common/mxstring.cpp
    LEGO1/omni/src/audio/mxsoundmanager.cpp
    LEGO1/omni/src/main/mxmain.cpp
    LEGO1/omni/src/notify/mxactionnotificationparam.cpp
    LEGO1/omni/src/common/mxobjectfactory.cpp
    LEGO1/omni/src/audio/mxsoundpresenter.cpp
    LEGO1/omni/src/audio/mxwavepresenter.cpp
    LEGO1/omni/src/video/mxvideopresenter.cpp
    LEGO1/omni/src/video/mxflcpresenter.cpp
    LEGO1/omni/src/video/mxsmkpresenter.cpp
    LEGO1/omni/src/video/mxloopingflcpresenter.cpp
    LEGO1/omni/src/video/mxloopingsmkpresenter.cpp
    LEGO1/omni/src/common/mxpresenter.cpp
    LEGO1/omni/src/common/mxmediapresenter.cpp
    LEGO1/omni/src/common/mxcompositepresenter.cpp
    LEGO1/omni/src/system/mxcriticalsection.cpp
    # The action-extra keyword table is an omni-side TU: retail seats its 40
    # globals at 0x10102048..0x101020e4, i.e. between mxcriticalsection's
    # .data and mxutilities', and a `lego1.dir` object's .data can never land
    # there (LINK emits every command-line object before any library member).
    # `g_parseExtraTokens` -- referenced by mxpresenter.cpp among others --
    # is what pulls it, immediately ahead of mxutilities' KeyValueStringParse,
    # reproducing retail's adjacency exactly.
    LEGO1/define.cpp
    LEGO1/omni/src/common/mxutilities.cpp
    LEGO1/omni/src/common/mxvariabletable.cpp
    LEGO1/omni/src/stream/mxdssubscriber.cpp
    LEGO1/omni/src/common/mxpresentationmanager.cpp
    LEGO1/omni/src/system/mxticklethread.cpp
    LEGO1/omni/src/audio/mxaudiomanager.cpp
    LEGO1/omni/src/system/mxautolock.cpp
    LEGO1/omni/src/stream/mxstreamer.cpp
    LEGO1/omni/src/video/mxstillpresenter.cpp
    LEGO1/omni/src/video/mxdisplaysurface.cpp
    LEGO1/omni/src/video/mxbitmap.cpp
    LEGO1/omni/src/video/flic.cpp
    LEGO1/omni/src/common/mxticklemanager.cpp
    LEGO1/omni/src/stream/mxdschunk.cpp
    LEGO1/omni/src/video/mxvideomanager.cpp
    LEGO1/omni/src/video/mxvideoparamflags.cpp
    LEGO1/omni/src/video/mxvideoparam.cpp
    LEGO1/omni/src/video/mxpalette.cpp
    LEGO1/omni/src/system/mxthread.cpp
    LEGO1/omni/src/action/mxdsobject.cpp
    LEGO1/omni/src/event/mxeventmanager.cpp
    LEGO1/omni/src/audio/mxmusicmanager.cpp
    LEGO1/omni/src/stream/mxstreamcontroller.cpp
    LEGO1/omni/src/audio/mxmusicpresenter.cpp
    LEGO1/omni/src/audio/mxmidipresenter.cpp
    LEGO1/omni/src/audio/mxloopingmidipresenter.cpp
    LEGO1/omni/src/event/mxeventpresenter.cpp
    LEGO1/omni/src/stream/mxstreamchunk.cpp
    LEGO1/omni/src/video/mxregion.cpp
    LEGO1/omni/src/video/mxsmk.cpp
    LEGO1/omni/src/stream/mxramstreamcontroller.cpp
    LEGO1/omni/src/stream/mxdsbuffer.cpp
    LEGO1/omni/src/stream/mxdiskstreamcontroller.cpp
    LEGO1/omni/src/system/mxsemaphore.cpp
    LEGO1/omni/src/action/mxdsobjectaction.cpp
    LEGO1/omni/src/action/mxdsmediaaction.cpp
    LEGO1/omni/src/action/mxdsanim.cpp
    LEGO1/omni/src/action/mxdssound.cpp
    LEGO1/omni/src/action/mxdsevent.cpp
    LEGO1/omni/src/action/mxdsstill.cpp
    LEGO1/omni/src/action/mxdsmultiaction.cpp
    LEGO1/omni/src/action/mxdsserialaction.cpp
    LEGO1/omni/src/action/mxdsparallelaction.cpp
    LEGO1/omni/src/action/mxdsselectaction.cpp
    LEGO1/omni/src/stream/mxdsfile.cpp
    LEGO1/omni/src/stream/mxio.cpp
    LEGO1/omni/src/action/mxdsstreamingaction.cpp
    LEGO1/omni/src/stream/mxramstreamprovider.cpp
    LEGO1/omni/src/stream/mxdiskstreamprovider.cpp
  )
  list(APPEND list_targets omni${ARG_SUFFIX})
  set_property(TARGET omni${ARG_SUFFIX} PROPERTY ARCHIVE_OUTPUT_NAME "omni$<$<CONFIG:Debug>:d>${ARG_SUFFIX}")
  target_include_directories(omni${ARG_SUFFIX} PRIVATE "${PROJECT_SOURCE_DIR}/LEGO1/omni/include" "${PROJECT_SOURCE_DIR}/LEGO1" "${PROJECT_SOURCE_DIR}/util")
  target_link_libraries(omni${ARG_SUFFIX} PRIVATE dsound winmm Smacker::Smacker)

  add_library(${NAME} SHARED
    LEGO1/res/lego1.rc
    LEGO1/lego/legoomni/src/worlds/score.cpp
    LEGO1/lego/legoomni/src/actors/helicopter.cpp
    LEGO1/lego/legoomni/src/worlds/gasstation.cpp
    LEGO1/lego/legoomni/src/audio/legocachsound.cpp
    LEGO1/lego/legoomni/src/common/legoobjectfactory.cpp
    LEGO1/lego/legoomni/src/actors/skateboard.cpp
    LEGO1/lego/legoomni/src/entity/legoentity.cpp
    LEGO1/lego/legoomni/src/audio/lego3dsound.cpp
    LEGO1/lego/legoomni/src/entity/legocameracontroller.cpp
    LEGO1/lego/legoomni/src/race/legoracers.cpp
    LEGO1/lego/legoomni/src/race/legoraceactor.cpp
    LEGO1/lego/legoomni/src/common/legostate.cpp
    LEGO1/lego/legoomni/src/actors/buildings.cpp
    LEGO1/lego/legoomni/src/common/misc.cpp
    LEGO1/lego/legoomni/src/race/legorace.cpp
    LEGO1/lego/legoomni/src/actors/pizzeria.cpp
    LEGO1/lego/legoomni/src/worlds/elevatorbottom.cpp
    LEGO1/lego/legoomni/src/audio/legoloadcachesoundpresenter.cpp
    LEGO1/lego/legoomni/src/actors/act2genactor.cpp
    LEGO1/lego/legoomni/src/actors/act2actor.cpp
    LEGO1/lego/legoomni/src/actors/islepathactor.cpp
    LEGO1/lego/legoomni/src/paths/legopathstruct.cpp
    LEGO1/lego/legoomni/src/paths/legoanimactor.cpp
    LEGO1/lego/legoomni/src/entity/legoworld.cpp
    LEGO1/lego/legoomni/src/build/legocarbuild.cpp
    LEGO1/lego/legoomni/src/common/legoplantmanager.cpp
    LEGO1/lego/legoomni/src/actors/bumpbouy.cpp
    LEGO1/modeldb/modeldb.cpp
    LEGO1/lego/legoomni/src/actors/racecar.cpp
    LEGO1/lego/legoomni/src/control/legocontrolmanager.cpp
    LEGO1/lego/legoomni/src/audio/legosoundmanager.cpp
    LEGO1/lego/legoomni/src/paths/legoextraactor.cpp
    LEGO1/lego/legoomni/src/actors/isleactor.cpp
    LEGO1/lego/legoomni/src/actors/radio.cpp
    LEGO1/lego/legoomni/src/entity/legoactor.cpp
    LEGO1/lego/legoomni/src/paths/legopathactor.cpp
    LEGO1/lego/legoomni/src/common/legobuildingmanager.cpp
    LEGO1/lego/legoomni/src/worlds/isle.cpp
    LEGO1/lego/legoomni/src/actors/motorcycle.cpp
    LEGO1/lego/legoomni/src/actors/ambulance.cpp
    LEGO1/lego/legoomni/src/worlds/infocenterdoor.cpp
    LEGO1/lego/legoomni/src/common/legovariables.cpp
    LEGO1/lego/legoomni/src/actors/pizza.cpp
    LEGO1/lego/legoomni/src/common/legogamestate.cpp
    LEGO1/lego/legoomni/src/audio/legocachesoundmanager.cpp
    LEGO1/lego/legoomni/src/common/legoutils.cpp
    LEGO1/lego/legoomni/src/actors/act3actors.cpp
    LEGO1/lego/legoomni/src/control/legometerpresenter.cpp
    LEGO1/lego/legoomni/src/common/legoactioncontrolpresenter.cpp
    LEGO1/lego/legoomni/src/common/mxcontrolpresenter.cpp
    LEGO1/lego/legoomni/src/paths/legopathpresenter.cpp
    LEGO1/lego/legoomni/src/common/legophoneme.cpp
    LEGO1/lego/legoomni/src/paths/legopathctrledge.cpp
    LEGO1/lego/legoomni/src/paths/legopathedgecontainer.cpp
    LEGO1/lego/legoomni/src/paths/legopathcontroller.cpp
    LEGO1/lego/legoomni/src/audio/lego3dwavepresenter.cpp
    LEGO1/lego/legoomni/src/common/legoanimmmpresenter.cpp
    LEGO1/lego/legoomni/src/common/mxtransitionmanager.cpp
    LEGO1/lego/legoomni/src/actors/towtrack.cpp
    LEGO1/lego/legoomni/src/entity/act2policestation.cpp
    LEGO1/lego/legoomni/src/video/legophonemepresenter.cpp
    LEGO1/lego/legoomni/src/video/legotexturepresenter.cpp
    LEGO1/lego/legoomni/src/worlds/legoact2.cpp
    LEGO1/lego/legoomni/src/main/scripts.cpp
    LEGO1/lego/legoomni/src/entity/legoentitypresenter.cpp
    LEGO1/lego/legoomni/src/actors/act3ammo.cpp
    LEGO1/lego/legoomni/src/entity/legonavcontroller.cpp
    LEGO1/lego/legoomni/src/paths/legopathboundary.cpp
    LEGO1/lego/legoomni/src/main/legomain.cpp
    LEGO1/lego/legoomni/src/input/legoinputmanager.cpp
    LEGO1/lego/legoomni/src/race/legoracemap.cpp
    LEGO1/lego/legoomni/src/worlds/jukebox.cpp
    LEGO1/lego/legoomni/src/video/legoflctexturepresenter.cpp
    LEGO1/lego/legoomni/src/worlds/police.cpp
    LEGO1/lego/legoomni/src/common/legoanimationmanager.cpp
    LEGO1/lego/legoomni/src/entity/legopovcontroller.cpp
    LEGO1/lego/legoomni/src/common/legotesttimer.cpp
    LEGO1/lego/legoomni/src/common/legotextureinfo.cpp
    LEGO1/lego/legoomni/src/actors/doors.cpp
    LEGO1/lego/legoomni/src/entity/legoworldpresenter.cpp
    LEGO1/lego/legoomni/src/actors/dunebuggy.cpp
    LEGO1/lego/legoomni/src/video/legoanimpresenter.cpp
    LEGO1/lego/legoomni/src/worlds/infocenter.cpp
    LEGO1/lego/legoomni/src/race/raceskel.cpp
    LEGO1/lego/legoomni/src/worlds/act3.cpp
    LEGO1/lego/legoomni/src/common/mxcompositemediapresenter.cpp
    LEGO1/lego/legoomni/src/worlds/hospital.cpp
    LEGO1/lego/legoomni/src/actors/bike.cpp
    LEGO1/lego/legoomni/src/entity/legoactorpresenter.cpp
    LEGO1/lego/legoomni/src/worlds/registrationbook.cpp
    LEGO1/lego/legoomni/src/build/legocarbuildpresenter.cpp
    LEGO1/lego/legoomni/src/video/legopalettepresenter.cpp
    LEGO1/lego/legoomni/src/entity/act2brick.cpp
    LEGO1/lego/legoomni/src/video/legovideomanager.cpp
    LEGO1/lego/legoomni/src/video/legopartpresenter.cpp
    LEGO1/lego/legoomni/src/actors/jetski.cpp
    LEGO1/lego/legoomni/src/audio/mxbackgroundaudiomanager.cpp
    LEGO1/lego/legoomni/src/video/legomodelpresenter.cpp
    LEGO1/lego/legoomni/src/race/legoracespecial.cpp
    LEGO1/lego/legoomni/src/worlds/historybook.cpp
    LEGO1/lego/legoomni/src/common/legoactors.cpp
    LEGO1/lego/legoomni/src/common/legocharactermanager.cpp
    LEGO1/lego/legoomni/src/actors/jukeboxentity.cpp
  )
  list(APPEND list_targets ${NAME})

  if (MINGW)
    target_compile_definitions(${NAME} PRIVATE DIRECTINPUT_VERSION=0x0500)
  endif()

  if (MSVC)
    target_sources(${NAME} PRIVATE LEGO1/LegoOmni.def)
  else()
    target_sources(${NAME} PRIVATE LEGO1/LegoOmni.mingw.def)
  endif()

  target_include_directories(${NAME} PUBLIC "${PROJECT_SOURCE_DIR}/util")
  target_include_directories(${NAME} PUBLIC "${PROJECT_SOURCE_DIR}/LEGO1")
  target_include_directories(${NAME} PUBLIC "${PROJECT_SOURCE_DIR}/LEGO1/omni/include")
  target_include_directories(${NAME} PUBLIC "${PROJECT_SOURCE_DIR}/LEGO1/lego/sources")
  target_include_directories(${NAME} PUBLIC "${PROJECT_SOURCE_DIR}/LEGO1/lego/legoomni/include")
  target_include_directories(${NAME} PUBLIC "${PROJECT_SOURCE_DIR}/LEGO1/lego/legoomni/include/actions")

  # Link libraries
  target_link_libraries(${NAME} PRIVATE
    ${ARG_LINK_LIBRARIES}
    dinput
    misc${ARG_SUFFIX}
    geom${ARG_SUFFIX}
    mxdirectx${ARG_SUFFIX}
    anim${ARG_SUFFIX}
    tglrl${ARG_SUFFIX}
    realtime${ARG_SUFFIX}
    viewmanager${ARG_SUFFIX}
    roi${ARG_SUFFIX}
    3dmanager${ARG_SUFFIX}
    omni${ARG_SUFFIX}
    shape${ARG_SUFFIX}
    Vec::Vec
    dxguid
  )

  foreach(tgt IN LISTS list_targets)
    target_link_libraries(${tgt} PRIVATE ${ARG_LINK_LIBRARIES})
    target_link_libraries(${tgt} PRIVATE $<$<BOOL:${ISLE_USE_DX5}>:DirectX5::DirectX5>)
    target_compile_definitions(${tgt} PRIVATE $<$<BOOL:${ISLE_USE_DX5}>:DIRECTX5_SDK>)
  endforeach()

  # Make sure filenames are ALL CAPS
  set_property(TARGET ${NAME} PROPERTY OUTPUT_NAME "${ARG_DLL_OUTPUT_NAME}")
  set_property(TARGET ${NAME} PROPERTY PREFIX "${ARG_DLL_PREFIX}")
  set_property(TARGET ${NAME} PROPERTY SUFFIX "${ARG_DLL_SUFFIX}")

  set(${ARG_OUT_TARGETS} ${list_targets} PARENT_SCOPE)
endfunction()

set(lego1_link_libraries )
if (ISLE_USE_SMARTHEAP)
  list(APPEND lego1_link_libraries SmartHeap::SmartHeap libcmt)
endif()

# 1997 scanned the OS/DirectX import libraries BEFORE the game's own static
# libraries, so the imports those static libraries demand arrive in a SECOND
# library pass. That is directly visible in the retail image: LEGO1.DLL's
# `.idata$6` hint/name pool is in library-scan order and comes out in two
# waves -- WINMM 3, DINPUT 1, KERNEL32 85, USER32 10, GDI32 9, then WINMM 12,
# DSOUND 1, DDRAW 2, KERNEL32 11, USER32 7, GDI32 6, d3drm 2. Listing these
# eight import libraries here (i.e. ahead of misc/geom/omni/... on the link
# line) reproduces that structure exactly, and the import-descriptor order
# with it. Purely a link-order property: no object changes, and reccmp is
# unaffected because it masks IAT operands.
list(APPEND lego1_link_libraries winmm dinput dsound ddraw kernel32 user32 gdi32 d3drm)

if(ISLE_BUILD_LEGO1)
  add_lego_libraries(lego1
    LINK_LIBRARIES ${lego1_link_libraries}
    DLL_OUTPUT_NAME "LEGO1"
    DLL_PREFIX ""
    DLL_SUFFIX ".DLL"
    OUT_TARGETS lego1_targets
  )
  reccmp_add_target(lego1 ID LEGO1)
endif()

if(ISLE_BUILD_BETA10)
  add_lego_libraries(beta10
    SUFFIX "-beta10"
    DLL_OUTPUT_NAME "BETA10"
    DLL_PREFIX ""
    DLL_SUFFIX ".DLL"
    OUT_TARGETS beta10_targets
  )
  reccmp_add_target(beta10 ID BETA10)

  # Enable `#ifdef BETA10` conditions
  target_compile_definitions(beta10 PRIVATE BETA10)
  foreach(tgt IN LISTS beta10_targets)
    target_compile_definitions(${tgt} PRIVATE BETA10)
  endforeach()
endif()

if (ISLE_BUILD_APP)
  add_executable(isle WIN32
    ISLE/res/isle.rc
    ISLE/isleapp.cpp
  )
  reccmp_add_target(isle ID ISLE)

  target_compile_definitions(isle PRIVATE ISLE_APP)

  # Use internal DirectX 5 if required
  target_link_libraries(isle PRIVATE $<$<BOOL:${ISLE_USE_DX5}>:DirectX5::DirectX5>)

  if (ISLE_USE_SMARTHEAP)
    target_link_libraries(isle PRIVATE SmartHeap::SmartHeap)
  endif()

  # Link DSOUND, WINMM, and LEGO1.
  # Goal 2: the .idata import-descriptor order IS the link line's library order,
  # and retail's is winmm, advapi32, gdi32, user32, dsound, Lego1, kernel32.
  # MEASURED (ISLE.EXE vs retail): .idata 4634 -> 988, .text 1289 -> 1130.
  # Later duplicates from the default library list are inert (a second occurrence
  # loads nothing new), and SmartHeap must stay first.
  target_link_libraries(isle PRIVATE winmm advapi32 gdi32 user32 dsound)
  if(ISLE_BUILD_LEGO1)
    target_link_libraries(isle PRIVATE lego1)
  else()
    target_link_libraries(isle PRIVATE beta10)
  endif()
  # kernel32 is deliberately NOT listed. Naming it here (or leaving it in CMake's
  # default library list) puts kernel32.lib AHEAD of LIBCMT in the search order,
  # so LINK scans it twice and pulls __IMPORT_DESCRIPTOR_KERNEL32 at the end of
  # the FIRST scan. That member carries the "KERNEL32.dll" name string, which
  # then lands in the MIDDLE of .idata$6 and displaces ~42 hint/name entries by
  # 12 bytes. Retail has it at the very END of .idata$6, i.e. kernel32.lib was
  # searched exactly once, after LIBCMT, reached only through the
  # /DEFAULTLIB:kernel32.lib directive the compiler embeds in every object.
  # MEASURED (ISLE.EXE vs retail): 1254 -> 486 differing bytes, .idata 988 -> 218.
  # Both occurrences must go; removing only one leaves 1248.
  # The import DESCRIPTOR order above is unaffected - kernel32 still comes last.
  string(REPLACE "kernel32.lib" "" CMAKE_CXX_STANDARD_LIBRARIES "${CMAKE_CXX_STANDARD_LIBRARIES}")
  string(REPLACE "kernel32.lib" "" CMAKE_C_STANDARD_LIBRARIES "${CMAKE_C_STANDARD_LIBRARIES}")

  # Make sure filenames are ALL CAPS
  set_property(TARGET isle PROPERTY OUTPUT_NAME ISLE)
  set_property(TARGET isle PROPERTY SUFFIX ".EXE")
endif()

if (ISLE_BUILD_CONFIG)
  add_executable(config WIN32
    LEGO1/mxdirectx/mxdirectxinfo.cpp
    LEGO1/mxdirectx/legodxinfo.cpp
    CONFIG/config.cpp
    CONFIG/ConfigCommandLineInfo.cpp
    CONFIG/MainDlg.cpp
    CONFIG/detectdx5.cpp
    CONFIG/StdAfx.cpp
    CONFIG/res/config.rc
  )
  reccmp_add_target(config ID CONFIG)
  target_compile_definitions(config PRIVATE _AFXDLL MXDIRECTX_FOR_CONFIG)
  target_include_directories(config PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/util" "${CMAKE_CURRENT_SOURCE_DIR}/LEGO1")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 14)
    target_link_libraries(config PRIVATE DirectX5::DirectX5)
  endif()
  target_compile_definitions(config PRIVATE DIRECT3D_VERSION=0x500)
  target_link_libraries(config PRIVATE ddraw dsound dxguid)
  set_property(TARGET config PROPERTY OUTPUT_NAME "CONFIG")
  set_property(TARGET config PROPERTY SUFFIX ".EXE")
  set_property(TARGET config PROPERTY MSVC_RUNTIME_LIBRARY MultiThreaded$<$<CONFIG:Debug>:Debug>DLL)
endif()

if (MSVC)
  if (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "15")
    set_property(TARGET ${lego1_targets} ${beta10_targets} APPEND PROPERTY COMPILE_DEFINITIONS "_CRT_SECURE_NO_WARNINGS")
    if (TARGET isle)
      target_compile_definitions(isle PRIVATE "_CRT_SECURE_NO_WARNINGS")
    endif()
    if (TARGET config)
      target_compile_definitions(config PRIVATE "_CRT_SECURE_NO_WARNINGS")
    endif()
  endif()
  # Visual Studio 2017 version 15.7 needs "/Zc:__cplusplus" for __cplusplus
  if (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "19.14.26428")
    foreach(tgt IN LISTS lego1_targets beta10_targets)
      target_compile_options(${tgt} PRIVATE "-Zc:__cplusplus")
    endforeach()
    if (TARGET isle)
      target_compile_options(isle PRIVATE "-Zc:__cplusplus")
    endif()
    if (TARGET config)
      target_compile_options(config PRIVATE "-Zc:__cplusplus")
    endif()
  endif()
endif()

if (ISLE_DECOMP_ASSERT)
    message(STATUS "Decomp asserts enabled")
    foreach(tgt IN LISTS lego1_targets beta10_targets)
      target_compile_definitions(${tgt} PRIVATE "ENABLE_DECOMP_ASSERTS")
    endforeach()

    if (TARGET isle)
      target_compile_definitions(isle PRIVATE "ENABLE_DECOMP_ASSERTS")
    endif()
    if (TARGET config)
      target_compile_definitions(config PRIVATE "ENABLE_DECOMP_ASSERTS")
    endif()
endif()

if (MSVC_FOR_DECOMP)
  # These flags have been taken from the defaults for a Visual C++ 4.20 project (the compiler the
  # game was originally built with) and tweaked slightly to produce more debugging info for reccmp.
  # They ensure a recompilation that can be byte/instruction accurate to the original binaries.
  if (ISLE_BUILD_APP)
    target_link_options(isle PRIVATE "/OPT:REF")
    # Goal 2 note: ISLE.EXE's CRT member load order is a single global FIFO seeded
    # by isleapp.obj's undefined-symbol table. Retail seats LIBCMT's hooks.obj
    # (terminate/unexpected/_inconsistency/__pInconsistency) at 0x4092e0. We used
    # to force that with /INCLUDE:?terminate@@YAXXZ, which reproduced the RESULT
    # by fiat but seated the member at the FRONT of the CRT region and left
    # .reloc's VirtualSize 28 bytes short. The CAUSE is a `delete[]` of a
    # destructible type in 1997's isleapp.cpp that /OPT:REF stripped -- see the
    # carrier at the end of ISLE/isleapp.cpp. With that in place the /INCLUDE is
    # actively harmful, so it is deliberately NOT used.
    set_property(TARGET isle ${lego1_targets} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  endif()

  if (ISLE_BUILD_CONFIG)
    target_link_options(config PRIVATE "/OPT:REF")
    # Import-descriptor order is library-scan order, and retail CONFIG.EXE's is
    # DDRAW, MFC42, MSVCRT, KERNEL32, USER32, ADVAPI32. Left implicit, MSVCRT
    # and KERNEL32 arrive only via /DEFAULTLIB after CMake's standard library
    # list, which puts USER32 and ADVAPI32 ahead of them. Naming them here --
    # the same thing `lego1_link_libraries` does for LEGO1, and for the same
    # reason -- reproduces retail's descriptor order exactly.
    # MEASURED: .idata differing 1577 -> 1537, CONFIG total 2881 -> 2837.
    target_link_libraries(config PRIVATE mfc42 msvcrt kernel32)
  endif()

  if (ISLE_INCLUDE_ENTROPY)
    message(STATUS "Using entropy file: ${ISLE_ENTROPY_FILENAME}")
    foreach(tgt IN LISTS lego1_targets beta10_targets)
      target_compile_options(${tgt} PRIVATE /FI${PROJECT_SOURCE_DIR}/${ISLE_ENTROPY_FILENAME})
    endforeach()
    if (TARGET isle)
      target_compile_options(isle PRIVATE /FI${PROJECT_SOURCE_DIR}/${ISLE_ENTROPY_FILENAME})
    endif()
    if (TARGET config)
      target_compile_options(config PRIVATE /FI${PROJECT_SOURCE_DIR}/${ISLE_ENTROPY_FILENAME})
    endif()
  endif()

  # Per-TU entropy: force-include a generated entropy header into individual
  # translation units. The manifest is a text file with lines of the form
  #   <source-path-relative-to-repo-root> <seed>
  # (blank lines and lines starting with # are ignored). Headers are generated
  # at configure time with tools/entropy.py, cached per seed in the build dir.
  set(ISLE_TU_ENTROPY_MANIFEST "" CACHE FILEPATH "Per-TU entropy manifest file")
  if (ISLE_TU_ENTROPY_MANIFEST)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    message(STATUS "Using per-TU entropy manifest: ${ISLE_TU_ENTROPY_MANIFEST}")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${ISLE_TU_ENTROPY_MANIFEST}")
    file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/tu-entropy")
    file(STRINGS "${ISLE_TU_ENTROPY_MANIFEST}" tu_entropy_lines)
    foreach(line IN LISTS tu_entropy_lines)
      if (line MATCHES "^[ \t]*(#.*)?$")
        continue()
      endif()
      separate_arguments(parts UNIX_COMMAND "${line}")
      list(LENGTH parts nparts)
      if (NOT nparts EQUAL 2)
        message(FATAL_ERROR "Malformed entropy manifest line: '${line}'")
      endif()
      list(GET parts 0 tu_src)
      list(GET parts 1 tu_seed)
      if (NOT EXISTS "${PROJECT_SOURCE_DIR}/${tu_src}")
        message(FATAL_ERROR "Entropy manifest references missing source: '${tu_src}'")
      endif()
      set(tu_hdr "${CMAKE_BINARY_DIR}/tu-entropy/entropy_${tu_seed}.h")
      if (NOT EXISTS "${tu_hdr}")
        execute_process(
          COMMAND ${Python3_EXECUTABLE} "${PROJECT_SOURCE_DIR}/tools/entropy.py" "${tu_seed}"
          OUTPUT_FILE "${tu_hdr}"
          RESULT_VARIABLE tu_rc
        )
        if (NOT tu_rc EQUAL 0 OR NOT EXISTS "${tu_hdr}")
          file(REMOVE "${tu_hdr}")
          message(FATAL_ERROR "tools/entropy.py failed for seed ${tu_seed}")
        endif()
      endif()
      set_property(SOURCE "${PROJECT_SOURCE_DIR}/${tu_src}" APPEND PROPERTY COMPILE_OPTIONS "/FI${tu_hdr}")
    endforeach()
  endif()

  # Setting the MSVC_RUNTIME_LIBRARY for all libraries as well as `lego1` produces the results
  # that are most consistent with the LEGO1.DLL and BETA10.DLL originals we have.
  # Equivalent to target_compile_options(... PRIVATE "/MT$<$<CONFIG:Debug>:d>")
  set_property(TARGET ${lego1_targets} ${beta10_targets} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  if(TARGET lego1)
    target_link_options(lego1 PRIVATE "/OPT:REF")
    set_property(TARGET lego1 PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  endif()

  set(CMAKE_CXX_FLAGS "/W3 /GX /D \"WIN32\" /D \"_WINDOWS\"")
  set(CMAKE_CXX_FLAGS_DEBUG "/Gm /Zi /Od /D \"_DEBUG\"")
  set(CMAKE_CXX_FLAGS_RELEASE "/O2 /D \"NDEBUG\"")
  set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/Zi /O2 /D \"NDEBUG\"")
  set(CMAKE_CXX_FLAGS_MINSIZEREL "/Os /D \"NDEBUG\"")

  set(CMAKE_EXE_LINKER_FLAGS "/machine:I386")
  set(CMAKE_EXE_LINKER_FLAGS_DEBUG "/incremental:yes /debug")
  set(CMAKE_EXE_LINKER_FLAGS_RELEASE "/incremental:no")
  set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "/incremental:no /debug")
  set(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL "/incremental:no")

  set(CMAKE_STATIC_LINKER_FLAGS "/machine:I386")

  set(CMAKE_SHARED_LINKER_FLAGS "/machine:I386")
  set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "/incremental:yes /debug")
  set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "/incremental:no")
  set(CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO "/incremental:no /debug")
  set(CMAKE_SHARED_LINKER_FLAGS_MINSIZEREL "/incremental:no")

  if(ISLE_BYTE_IDENTICAL)
    # Goal 2 (byte-identical binaries): the retail images carry NO debug data
    # directory, while linking with /debug adds one (a 28-byte
    # IMAGE_DEBUG_DIRECTORY plus its MISC record) at the head of .rdata --
    # measured at 88 bytes in ISLE.EXE.
    #
    # Drop ONLY the linker's /debug. /Zi MUST STAY: it is a compile flag, and
    # removing it measurably CHANGES CODEGEN -- 31 of 561 COMDATs in the first
    # 16 objects flipped, all of them commutative `cmp` operand-direction
    # tie-breaks. Debug records occupy the compiler's symbol arena, which is
    # exactly the entropy channel this project's per-TU tuning rides on, so a
    # /Zi-less build silently re-rolls the tuned state. Compile identically,
    # link without debug info.
    foreach(_cfg "" _DEBUG _RELEASE _RELWITHDEBINFO _MINSIZEREL)
      foreach(_kind EXE SHARED STATIC)
        string(REPLACE "/debug" "" CMAKE_${_kind}_LINKER_FLAGS${_cfg}
               "${CMAKE_${_kind}_LINKER_FLAGS${_cfg}}")
      endforeach()
    endforeach()
    message(STATUS "ISLE_BYTE_IDENTICAL: linking without /debug (no DEBUG data directory); /Zi retained so codegen is unchanged")

    # Two classes of bytes are stamped from the wall clock at link time and are
    # not derivable from source: the COFF header's TimeDateStamp, and every
    # TimeDateStamp in the .rsrc resource directory tree. MSVC 4.20's linker has
    # no switch for either, so restore them from the original binary after the
    # link. Measured on ISLE.EXE: 76 bytes (4 + 72 across 18 resource nodes).
    set(ISLE_ORIGINAL_DIR "${PROJECT_SOURCE_DIR}/legobin" CACHE PATH
        "Directory holding the original retail binaries, used by ISLE_BYTE_IDENTICAL to restore link-time timestamps")
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(NOT Python3_Interpreter_FOUND)
      set(Python3_EXECUTABLE python3)
    endif()
    foreach(_t isle lego1 config)
      if(TARGET ${_t})
        get_property(_out TARGET ${_t} PROPERTY OUTPUT_NAME)
        get_property(_sfx TARGET ${_t} PROPERTY SUFFIX)
        if(EXISTS "${ISLE_ORIGINAL_DIR}/${_out}${_sfx}")
          add_custom_command(TARGET ${_t} POST_BUILD
            COMMAND "${Python3_EXECUTABLE}"
                    "${PROJECT_SOURCE_DIR}/tools/pe_stamp.py"
                    "$<TARGET_FILE:${_t}>"
                    "${ISLE_ORIGINAL_DIR}/${_out}${_sfx}"
            COMMENT "Restoring original PE/resource timestamps in ${_out}${_sfx}"
            VERBATIM)
        else()
          message(STATUS "ISLE_BYTE_IDENTICAL: no original at ${ISLE_ORIGINAL_DIR}/${_out}${_sfx}, timestamps left as linked")
        endif()
      endif()
    endforeach()
  endif()

  # Older MSVC versions don't support building in parallel.
  # Force non-parallel builds of isle and lego1 by putting them in a pool with 1 available job.
  # Giving every object its own PDB (see ISLE_PER_OBJECT_PDB) removes the shared
  # resource, so the 1-job pools are only needed when that option is off.
  if (CMAKE_CXX_COMPILER_ID VERSION_LESS 12 AND NOT ISLE_PER_OBJECT_PDB)
    foreach(tgt IN LISTS lego1_targets beta10_targets)
      set_property(GLOBAL APPEND PROPERTY JOB_POOLS "msvc_${tgt}=1")
      set_property(TARGET ${tgt} PROPERTY JOB_POOL_COMPILE "msvc_${tgt}")
      set_property(TARGET ${tgt} PROPERTY JOB_POOL_LINK "msvc_${tgt}")
    endforeach()
    if (TARGET isle)
      set_property(GLOBAL APPEND PROPERTY JOB_POOLS "msvc_isle=1")
      set_property(TARGET isle PROPERTY JOB_POOL_COMPILE "msvc_isle")
      set_property(TARGET isle PROPERTY JOB_POOL_LINK "msvc_isle")
    endif()
    if (TARGET config)
      set_property(GLOBAL APPEND PROPERTY JOB_POOLS "msvc_config=1")
      set_property(TARGET config PROPERTY JOB_POOL_COMPILE "msvc_config")
      set_property(TARGET config PROPERTY JOB_POOL_LINK "msvc_config")
    endif()
  endif()
endif()

find_program(CLANGFORMAT_BIN NAMES clang-format)
if(EXISTS "${CLANGFORMAT_BIN}")
  execute_process(COMMAND "${CLANGFORMAT_BIN}" --version
    OUTPUT_VARIABLE "CLANGFORMAT_VERSION_OUTPUT"
    RESULT_VARIABLE "CLANGFORMAT_RESULT"
  )
  if(CLANGFORMAT_RESULT EQUAL 0 AND CLANGFORMAT_VERSION_OUTPUT MATCHES "version ([0-9\\.]+)")
    set(CLANGFORMAT_VERSION "${CMAKE_MATCH_1}")
    set(CLANGFORMAT_VERSION_REQUIRED "17.0")
    message(DEBUG "Found clang-format version ${CLANGFORMAT_VERSION} (needs ${CLANGFORMAT_VERSION_REQUIRED}")
    if(CLANGFORMAT_VERSION VERSION_GREATER_EQUAL "${CLANGFORMAT_VERSION_REQUIRED}")
      file(GLOB_RECURSE isle_sources
        "${PROJECT_SOURCE_DIR}/ISLE/*.cpp"
        "${PROJECT_SOURCE_DIR}/ISLE/*.h"
        "${PROJECT_SOURCE_DIR}/LEGO1/*.cpp"
        "${PROJECT_SOURCE_DIR}/LEGO1/*.h"
      )
      string(REPLACE ";" "\n" isle_sources_lines "${isle_sources}")
      file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/isle_sources.txt" "${isle_sources_lines}\n")
      add_custom_target(clang-format ${CLANGFORMAT_BIN} -i "--files=${CMAKE_CURRENT_BINARY_DIR}/isle_sources.txt")
    endif()
  endif()
endif()

reccmp_configure()
