cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

# MSVC runtime library flags are selected by an abstraction
cmake_policy(SET CMP0091 NEW)

project(isle CXX)

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
set_property(TARGET Smacker::Smacker PROPERTY IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/3rdparty/smacker/smack.lib")
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
    LEGO1/tgl/d3drm/renderer.cpp
    LEGO1/tgl/d3drm/texture.cpp
    LEGO1/tgl/d3drm/view.cpp
    LEGO1/tgl/d3drm/device.cpp
    LEGO1/tgl/d3drm/group.cpp
    LEGO1/tgl/d3drm/camera.cpp
    LEGO1/tgl/d3drm/light.cpp
    LEGO1/tgl/d3drm/meshbuilder.cpp
    LEGO1/tgl/d3drm/mesh.cpp
  )
  list(APPEND list_targets tglrl${ARG_SUFFIX})
  set_property(TARGET tglrl${ARG_SUFFIX} PROPERTY ARCHIVE_OUTPUT_NAME "tglrl40$<$<CONFIG:Debug>:d>${ARG_SUFFIX}")
  target_include_directories(tglrl${ARG_SUFFIX} PRIVATE "${PROJECT_SOURCE_DIR}/LEGO1" "${PROJECT_SOURCE_DIR}/util")
  target_link_libraries(tglrl${ARG_SUFFIX} PRIVATE d3drm)

  add_library(realtime${ARG_SUFFIX} STATIC
    LEGO1/realtime/orientableroi.cpp
    LEGO1/realtime/realtime.cpp
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
    LEGO1/viewmanager/viewroi.cpp
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

  add_library(roi${ARG_SUFFIX} STATIC
    LEGO1/lego/sources/roi/legoroi.cpp
    LEGO1/lego/sources/roi/legolod.cpp
  )
  list(APPEND list_targets roi${ARG_SUFFIX})
  set_property(TARGET roi${ARG_SUFFIX} PROPERTY ARCHIVE_OUTPUT_NAME "roi$<$<CONFIG:Debug>:d>${ARG_SUFFIX}")
  target_include_directories(roi${ARG_SUFFIX} PRIVATE "${PROJECT_SOURCE_DIR}/LEGO1/omni/include" "${PROJECT_SOURCE_DIR}/LEGO1" "${PROJECT_SOURCE_DIR}/LEGO1/lego/sources" "${PROJECT_SOURCE_DIR}/util")
  target_link_libraries(roi${ARG_SUFFIX} PRIVATE viewmanager${ARG_SUFFIX} Vec::Vec)

  add_library(geom${ARG_SUFFIX} STATIC
    LEGO1/lego/sources/geom/legoedge.cpp
    LEGO1/lego/sources/geom/legoweedge.cpp
    LEGO1/lego/sources/geom/legounkown100db7f4.cpp
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
    LEGO1/lego/sources/misc/legostorage.cpp
    LEGO1/lego/sources/misc/legoimage.cpp
    LEGO1/lego/sources/misc/legocontainer.cpp
    LEGO1/lego/sources/misc/legotree.cpp
    LEGO1/lego/sources/misc/legounknown.cpp
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
    LEGO1/omni/src/main/mxomni.cpp
    LEGO1/omni/src/notify/mxactionnotificationparam.cpp
    LEGO1/omni/src/main/mxomnicreateflags.cpp
    LEGO1/omni/src/main/mxomnicreateparam.cpp
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
    LEGO1/omni/src/common/mxutilities.cpp
    LEGO1/omni/src/common/mxvariabletable.cpp
    LEGO1/omni/src/stream/mxdssubscriber.cpp
    LEGO1/omni/src/common/mxmediamanager.cpp
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
    LEGO1/omni/src/system/mxscheduler.cpp
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
    LEGO1/lego/legoomni/src/actors/buildingentity.cpp
    LEGO1/lego/legoomni/src/actors/buildings.cpp
    LEGO1/lego/legoomni/src/common/misc.cpp
    LEGO1/lego/legoomni/src/race/legorace.cpp
    LEGO1/lego/legoomni/src/race/jetskirace.cpp
    LEGO1/lego/legoomni/src/race/carrace.cpp
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
    LEGO1/lego/legoomni/src/common/legotextureinfo.cpp
    LEGO1/lego/legoomni/src/actors/doors.cpp
    LEGO1/lego/legoomni/src/entity/legoworldpresenter.cpp
    LEGO1/lego/legoomni/src/actors/dunebuggy.cpp
    LEGO1/lego/legoomni/src/video/legoanimpresenter.cpp
    LEGO1/lego/legoomni/src/video/legoloopinganimpresenter.cpp
    LEGO1/lego/legoomni/src/video/legolocomotionanimpresenter.cpp
    LEGO1/lego/legoomni/src/video/legohideanimpresenter.cpp
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
    LEGO1/lego/legoomni/src/common/legocharactermanager.cpp
    LEGO1/lego/legoomni/src/actors/jukeboxentity.cpp
    # We need to get rid of / refactor the below units into existing/other ones
    LEGO1/main.cpp
    LEGO1/lego/legoomni/src/entity/legolocations.cpp
    LEGO1/lego/legoomni/src/common/legoactors.cpp
    LEGO1/lego/legoomni/src/common/legoplants.cpp
    LEGO1/define.cpp
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
  list(APPEND lego1_link_libraries SmartHeap::SmartHeap)
endif()

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
  target_compile_definitions(beta10 PRIVATE BETA10)
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

  # Link DSOUND, WINMM, and LEGO1
  target_link_libraries(isle PRIVATE dsound winmm)
  if(ISLE_BUILD_LEGO1)
    target_link_libraries(isle PRIVATE lego1)
  else()
    target_link_libraries(isle PRIVATE beta10)
  endif()

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
    CONFIG/AboutDlg.cpp
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
  target_link_libraries(config PRIVATE ddraw dxguid)
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
    set_property(TARGET isle ${lego1_targets} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  endif()

  if(TARGET lego1)
    target_link_options(lego1 PRIVATE "/OPT:REF")
    # Equivalent to target_compile_options(... PRIVATE "/MT$<$<CONFIG:Debug>:d>")
    set_property(TARGET lego1 ${lego1_targets} ${beta10_targets} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
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

  # Older MSVC versions don't support building in parallel.
  # Force non-parallel builds of isle and lego1 by putting them in a pool with 1 available job.
  if (CMAKE_CXX_COMPILER_ID VERSION_LESS 12)
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
