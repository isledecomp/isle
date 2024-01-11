cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(isle CXX)

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

message(STATUS "MSVC for decompilation: ${MSVC_FOR_DECOMP}")

option(ISLE_BUILD_APP "Build ISLE.EXE application" ON)
option(ISLE_USE_SMARTHEAP "Build with SmartHeap" ${MSVC_FOR_DECOMP})
option(ISLE_USE_DX5 "Build with internal DirectX 5 SDK" ON)

add_library(lego1 SHARED
  LEGO1/define.cpp
  LEGO1/lego/legoomni/src/act1/act1state.cpp
  LEGO1/lego/legoomni/src/act2/act2brick.cpp
  LEGO1/lego/legoomni/src/act2/act2policestation.cpp
  LEGO1/lego/legoomni/src/act2/legoact2state.cpp
  LEGO1/lego/legoomni/src/act3/act3.cpp
  LEGO1/lego/legoomni/src/act3/act3shark.cpp
  LEGO1/lego/legoomni/src/act3/act3state.cpp
  LEGO1/lego/legoomni/src/audio/legocachesound.cpp
  LEGO1/lego/legoomni/src/audio/legoloadcachesoundpresenter.cpp
  LEGO1/lego/legoomni/src/audio/legosoundmanager.cpp
  LEGO1/lego/legoomni/src/audio/mxbackgroundaudiomanager.cpp
  LEGO1/lego/legoomni/src/build/buildingentity.cpp
  LEGO1/lego/legoomni/src/build/dunebuggy.cpp
  LEGO1/lego/legoomni/src/build/helicopter.cpp
  LEGO1/lego/legoomni/src/build/helicopterstate.cpp
  LEGO1/lego/legoomni/src/build/jetski.cpp
  LEGO1/lego/legoomni/src/build/legobuildingmanager.cpp
  LEGO1/lego/legoomni/src/build/legocarbuild.cpp
  LEGO1/lego/legoomni/src/build/legovehiclebuildstate.cpp
  LEGO1/lego/legoomni/src/build/racecar.cpp
  LEGO1/lego/legoomni/src/common/animstate.cpp
  LEGO1/lego/legoomni/src/common/gifmanager.cpp
  LEGO1/lego/legoomni/src/common/legoactioncontrolpresenter.cpp
  LEGO1/lego/legoomni/src/common/legobackgroundcolor.cpp
  LEGO1/lego/legoomni/src/common/legofullscreenmovie.cpp
  LEGO1/lego/legoomni/src/common/legogamestate.cpp
  LEGO1/lego/legoomni/src/common/legoobjectfactory.cpp
  LEGO1/lego/legoomni/src/common/legoplantmanager.cpp
  LEGO1/lego/legoomni/src/common/legostate.cpp
  LEGO1/lego/legoomni/src/common/legostream.cpp
  LEGO1/lego/legoomni/src/common/legounksavedatawriter.cpp
  LEGO1/lego/legoomni/src/common/legoutil.cpp
  LEGO1/lego/legoomni/src/common/mxcompositemediapresenter.cpp
  LEGO1/lego/legoomni/src/control/legocontrolmanager.cpp
  LEGO1/lego/legoomni/src/control/mxcontrolpresenter.cpp
  LEGO1/lego/legoomni/src/entity/legoactor.cpp
  LEGO1/lego/legoomni/src/entity/legoanimactor.cpp
  LEGO1/lego/legoomni/src/entity/legocameracontroller.cpp
  LEGO1/lego/legoomni/src/entity/legoentity.cpp
  LEGO1/lego/legoomni/src/entity/legoentitypresenter.cpp
  LEGO1/lego/legoomni/src/entity/legojetski.cpp
  LEGO1/lego/legoomni/src/entity/legonavcontroller.cpp
  LEGO1/lego/legoomni/src/entity/legopathactor.cpp
  LEGO1/lego/legoomni/src/entity/legopovcontroller.cpp
  LEGO1/lego/legoomni/src/entity/legorace.cpp
  LEGO1/lego/legoomni/src/entity/legoworld.cpp
  LEGO1/lego/legoomni/src/entity/legoworldpresenter.cpp
  LEGO1/lego/legoomni/src/gasstation/gasstation.cpp
  LEGO1/lego/legoomni/src/gasstation/gasstationentity.cpp
  LEGO1/lego/legoomni/src/gasstation/gasstationstate.cpp
  LEGO1/lego/legoomni/src/hospital/ambulance.cpp
  LEGO1/lego/legoomni/src/hospital/ambulancemissionstate.cpp
  LEGO1/lego/legoomni/src/hospital/hospital.cpp
  LEGO1/lego/legoomni/src/hospital/hospitalentity.cpp
  LEGO1/lego/legoomni/src/hospital/hospitalstate.cpp
  LEGO1/lego/legoomni/src/infocenter/elevatorbottom.cpp
  LEGO1/lego/legoomni/src/infocenter/infocenter.cpp
  LEGO1/lego/legoomni/src/infocenter/infocenterdoor.cpp
  LEGO1/lego/legoomni/src/infocenter/infocenterentity.cpp
  LEGO1/lego/legoomni/src/infocenter/infocenterstate.cpp
  LEGO1/lego/legoomni/src/infocenter/registrationbook.cpp
  LEGO1/lego/legoomni/src/infocenter/score.cpp
  LEGO1/lego/legoomni/src/infocenter/scorestate.cpp
  LEGO1/lego/legoomni/src/input/legoinputmanager.cpp
  LEGO1/lego/legoomni/src/isle/beachhouseentity.cpp
  LEGO1/lego/legoomni/src/isle/bike.cpp
  LEGO1/lego/legoomni/src/isle/bumpbouy.cpp
  LEGO1/lego/legoomni/src/isle/historybook.cpp
  LEGO1/lego/legoomni/src/isle/isleactor.cpp
  LEGO1/lego/legoomni/src/isle/isle.cpp
  LEGO1/lego/legoomni/src/isle/islepathactor.cpp
  LEGO1/lego/legoomni/src/isle/jukebox.cpp
  LEGO1/lego/legoomni/src/isle/jukeboxentity.cpp
  LEGO1/lego/legoomni/src/isle/jukeboxstate.cpp
  LEGO1/lego/legoomni/src/isle/motorcycle.cpp
  LEGO1/lego/legoomni/src/isle/radio.cpp
  LEGO1/lego/legoomni/src/isle/radiostate.cpp
  LEGO1/lego/legoomni/src/isle/skateboard.cpp
  LEGO1/lego/legoomni/src/main/legoomni.cpp
  LEGO1/lego/legoomni/src/notify/legoeventnotificationparam.cpp
  LEGO1/lego/legoomni/src/paths/legopathcontroller.cpp
  LEGO1/lego/legoomni/src/paths/legopathpresenter.cpp
  LEGO1/lego/legoomni/src/pizzeria/pizza.cpp
  LEGO1/lego/legoomni/src/pizzeria/pizzamissionstate.cpp
  LEGO1/lego/legoomni/src/pizzeria/pizzeria.cpp
  LEGO1/lego/legoomni/src/pizzeria/pizzeriastate.cpp
  LEGO1/lego/legoomni/src/police/police.cpp
  LEGO1/lego/legoomni/src/police/policeentity.cpp
  LEGO1/lego/legoomni/src/police/policestate.cpp
  LEGO1/lego/legoomni/src/race/carrace.cpp
  LEGO1/lego/legoomni/src/race/jetskirace.cpp
  LEGO1/lego/legoomni/src/race/racestandsentity.cpp
  LEGO1/lego/legoomni/src/race/racestate.cpp
  LEGO1/lego/legoomni/src/towtrack/towtrack.cpp
  LEGO1/lego/legoomni/src/towtrack/towtrackmissionstate.cpp
  LEGO1/lego/legoomni/src/unknown/legounknown100d7c88.cpp
  LEGO1/lego/legoomni/src/video/legoanimationmanager.cpp
  LEGO1/lego/legoomni/src/video/legoanimmmpresenter.cpp
  LEGO1/lego/legoomni/src/video/legoanimpresenter.cpp
  LEGO1/lego/legoomni/src/video/legocarbuildanimpresenter.cpp
  LEGO1/lego/legoomni/src/video/legoflctexturepresenter.cpp
  LEGO1/lego/legoomni/src/video/legohideanimpresenter.cpp
  LEGO1/lego/legoomni/src/video/legolocomotionanimpresenter.cpp
  LEGO1/lego/legoomni/src/video/legometerpresenter.cpp
  LEGO1/lego/legoomni/src/video/legomodelpresenter.cpp
  LEGO1/lego/legoomni/src/video/legopalettepresenter.cpp
  LEGO1/lego/legoomni/src/video/legopartpresenter.cpp
  LEGO1/lego/legoomni/src/video/legophonemepresenter.cpp
  LEGO1/lego/legoomni/src/video/legotexturepresenter.cpp
  LEGO1/lego/legoomni/src/video/legovideomanager.cpp
  LEGO1/lego/legoomni/src/video/mxtransitionmanager.cpp
  LEGO1/lego/sources/3dmanager/lego3dmanager.cpp
  LEGO1/lego/sources/3dmanager/lego3dview.cpp
  LEGO1/lego/sources/3dmanager/legoview1.cpp
  LEGO1/lego/sources/3dmanager/tglsurface.cpp
  LEGO1/lego/sources/roi/legoroi.cpp
  LEGO1/main.cpp
  LEGO1/mxdirectx/mxdirect3d.cpp
  LEGO1/mxdirectx/mxdirectdraw.cpp
  LEGO1/omni/src/action/mxdsaction.cpp
  LEGO1/omni/src/action/mxdsanim.cpp
  LEGO1/omni/src/action/mxdsevent.cpp
  LEGO1/omni/src/action/mxdsmediaaction.cpp
  LEGO1/omni/src/action/mxdsmultiaction.cpp
  LEGO1/omni/src/action/mxdsobjectaction.cpp
  LEGO1/omni/src/action/mxdsobject.cpp
  LEGO1/omni/src/action/mxdsparallelaction.cpp
  LEGO1/omni/src/action/mxdsselectaction.cpp
  LEGO1/omni/src/action/mxdsserialaction.cpp
  LEGO1/omni/src/action/mxdssound.cpp
  LEGO1/omni/src/action/mxdsstill.cpp
  LEGO1/omni/src/action/mxdsstreamingaction.cpp
  LEGO1/omni/src/audio/mxaudiomanager.cpp
  LEGO1/omni/src/audio/mxaudiopresenter.cpp
  LEGO1/omni/src/audio/mxloopingmidipresenter.cpp
  LEGO1/omni/src/audio/mxmidipresenter.cpp
  LEGO1/omni/src/audio/mxmusicmanager.cpp
  LEGO1/omni/src/audio/mxmusicpresenter.cpp
  LEGO1/omni/src/audio/mxsoundmanager.cpp
  LEGO1/omni/src/audio/mxsoundpresenter.cpp
  LEGO1/omni/src/audio/mxwavepresenter.cpp
  LEGO1/omni/src/common/mxatomidcounter.cpp
  LEGO1/omni/src/common/mxatomid.cpp
  LEGO1/omni/src/common/mxcompositepresenter.cpp
  LEGO1/omni/src/common/mxcore.cpp
  LEGO1/omni/src/common/mxmediamanager.cpp
  LEGO1/omni/src/common/mxmediapresenter.cpp
  LEGO1/omni/src/common/mxobjectfactory.cpp
  LEGO1/omni/src/common/mxpresenter.cpp
  LEGO1/omni/src/common/mxstring.cpp
  LEGO1/omni/src/common/mxticklemanager.cpp
  LEGO1/omni/src/common/mxtimer.cpp
  LEGO1/omni/src/common/mxutil.cpp
  LEGO1/omni/src/common/mxvariable.cpp
  LEGO1/omni/src/common/mxvariabletable.cpp
  LEGO1/omni/src/entity/mxentity.cpp
  LEGO1/omni/src/event/mxeventmanager.cpp
  LEGO1/omni/src/event/mxeventpresenter.cpp
  LEGO1/omni/src/main/mxomni.cpp
  LEGO1/omni/src/main/mxomnicreateflags.cpp
  LEGO1/omni/src/main/mxomnicreateparam.cpp
  LEGO1/omni/src/notify/mxactionnotificationparam.cpp
  LEGO1/omni/src/notify/mxnotificationmanager.cpp
  LEGO1/omni/src/notify/mxnotificationparam.cpp
  LEGO1/omni/src/notify/mxtype17notificationparam.cpp
  LEGO1/omni/src/stream/mxdiskstreamcontroller.cpp
  LEGO1/omni/src/stream/mxdiskstreamprovider.cpp
  LEGO1/omni/src/stream/mxdsbuffer.cpp
  LEGO1/omni/src/stream/mxdschunk.cpp
  LEGO1/omni/src/stream/mxdsfile.cpp
  LEGO1/omni/src/stream/mxdssource.cpp
  LEGO1/omni/src/stream/mxdssubscriber.cpp
  LEGO1/omni/src/stream/mxioinfo.cpp
  LEGO1/omni/src/stream/mxramstreamcontroller.cpp
  LEGO1/omni/src/stream/mxramstreamprovider.cpp
  LEGO1/omni/src/stream/mxstreamchunk.cpp
  LEGO1/omni/src/stream/mxstreamcontroller.cpp
  LEGO1/omni/src/stream/mxstreamer.cpp
  LEGO1/omni/src/stream/mxstreamlist.cpp
  LEGO1/omni/src/stream/mxstreamprovider.cpp
  LEGO1/omni/src/system/mxautolocker.cpp
  LEGO1/omni/src/system/mxcriticalsection.cpp
  LEGO1/omni/src/system/mxscheduler.cpp
  LEGO1/omni/src/system/mxsemaphore.cpp
  LEGO1/omni/src/system/mxthread.cpp
  LEGO1/omni/src/video/mxbitmap.cpp
  LEGO1/omni/src/video/mxdisplaysurface.cpp
  LEGO1/omni/src/video/mxflcpresenter.cpp
  LEGO1/omni/src/video/mxloopingflcpresenter.cpp
  LEGO1/omni/src/video/mxloopingsmkpresenter.cpp
  LEGO1/omni/src/video/mxpalette.cpp
  LEGO1/omni/src/video/mxregion.cpp
  LEGO1/omni/src/video/mxregioncursor.cpp
  LEGO1/omni/src/video/mxsmack.cpp
  LEGO1/omni/src/video/mxsmkpresenter.cpp
  LEGO1/omni/src/video/mxstillpresenter.cpp
  LEGO1/omni/src/video/mxvideomanager.cpp
  LEGO1/omni/src/video/mxvideoparam.cpp
  LEGO1/omni/src/video/mxvideoparamflags.cpp
  LEGO1/omni/src/video/mxvideopresenter.cpp
  LEGO1/realtime/matrix.cpp
  LEGO1/realtime/orientableroi.cpp
  LEGO1/realtime/realtime.cpp
  LEGO1/realtime/realtimeview.cpp
  LEGO1/realtime/vector.cpp
  LEGO1/tgl/d3drm/camera.cpp
  LEGO1/tgl/d3drm/device.cpp
  LEGO1/tgl/d3drm/group.cpp
  LEGO1/tgl/d3drm/light.cpp
  LEGO1/tgl/d3drm/mesh.cpp
  LEGO1/tgl/d3drm/renderer.cpp
  LEGO1/tgl/d3drm/texture.cpp
  LEGO1/tgl/d3drm/unk.cpp
  LEGO1/tgl/d3drm/view.cpp
  LEGO1/viewmanager/viewlodlist.cpp
  LEGO1/viewmanager/viewmanager.cpp
  LEGO1/viewmanager/viewroi.cpp
)

if (MINGW)
  target_compile_definitions(lego1 PRIVATE DIRECTINPUT_VERSION=0x0500)
endif()

target_include_directories(lego1 PRIVATE "${CMAKE_SOURCE_DIR}/util")
target_include_directories(lego1 PRIVATE "${CMAKE_SOURCE_DIR}/LEGO1")
target_include_directories(lego1 PRIVATE "${CMAKE_SOURCE_DIR}/LEGO1/omni/include")
target_include_directories(lego1 PRIVATE "${CMAKE_SOURCE_DIR}/LEGO1/lego/sources")
target_include_directories(lego1 PRIVATE "${CMAKE_SOURCE_DIR}/LEGO1/lego/legoomni/include")

# Additional include directories
target_include_directories(lego1 PUBLIC "${CMAKE_SOURCE_DIR}/3rdparty/vec")
target_include_directories(lego1 PRIVATE "${CMAKE_SOURCE_DIR}/3rdparty/flic")
target_include_directories(lego1 PRIVATE "${CMAKE_SOURCE_DIR}/3rdparty/smacker")

if (ISLE_USE_SMARTHEAP)
  add_library(SmartHeap::SmartHeap STATIC IMPORTED)
  set_target_properties(SmartHeap::SmartHeap PROPERTIES
    IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/3rdparty/smartheap/SHLW32MT.LIB"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/3rdparty/smartheap"
    INTERFACE_COMPILE_OPTIONS "/FI${CMAKE_SOURCE_DIR}/3rdparty/smartheap/SMRTHEAP.HPP")

  target_link_libraries(lego1 PRIVATE SmartHeap::SmartHeap)
endif()

# Use internal DirectX 5 if required
if (ISLE_USE_DX5)
  target_include_directories(lego1 PRIVATE "${CMAKE_SOURCE_DIR}/3rdparty/dx5/inc")
  target_link_directories(lego1 PRIVATE "${CMAKE_SOURCE_DIR}/3rdparty/dx5/lib")
endif()

target_link_directories(lego1 PRIVATE "${CMAKE_SOURCE_DIR}/3rdparty/smacker")

# Link libraries
target_link_libraries(lego1 PRIVATE ddraw dsound dinput dxguid winmm d3drm smack)

# Make sure filenames are ALL CAPS
set_property(TARGET lego1 PROPERTY OUTPUT_NAME LEGO1)
set_property(TARGET lego1 PROPERTY PREFIX "")
set_property(TARGET lego1 PROPERTY SUFFIX ".DLL")

if (ISLE_BUILD_APP)
  add_executable(isle WIN32
    ISLE/res/isle.rc
    ISLE/isleapp.cpp
    ISLE/define.cpp
  )

  target_compile_definitions(isle PRIVATE ISLE_APP)

  target_include_directories(isle PRIVATE "${CMAKE_SOURCE_DIR}/util")
  target_include_directories(isle PRIVATE "${CMAKE_SOURCE_DIR}/LEGO1")
  target_include_directories(isle PRIVATE "${CMAKE_SOURCE_DIR}/LEGO1/omni/include")
  target_include_directories(isle PRIVATE "${CMAKE_SOURCE_DIR}/LEGO1/lego/sources")
  target_include_directories(isle PRIVATE "${CMAKE_SOURCE_DIR}/LEGO1/lego/legoomni/include")

  # Use internal DirectX 5 if required
  if (ISLE_USE_DX5)
    target_include_directories(isle PRIVATE "${CMAKE_SOURCE_DIR}/3rdparty/dx5/inc")
    target_link_directories(isle PRIVATE "${CMAKE_SOURCE_DIR}/3rdparty/dx5/lib")
  endif()

  if (ISLE_USE_SMARTHEAP)
    target_link_libraries(isle PRIVATE SmartHeap::SmartHeap)
  endif()

  # Link DSOUND, WINMM, and LEGO1
  target_link_libraries(isle PRIVATE dsound winmm lego1)

  # Make sure filenames are ALL CAPS
  set_property(TARGET isle PROPERTY OUTPUT_NAME ISLE)
  set_property(TARGET isle PROPERTY SUFFIX ".EXE")
endif()

if (MSVC)
  if (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "15")
    target_compile_definitions(lego1 PRIVATE _CRT_SECURE_NO_WARNINGS)
    if (ISLE_BUILD_APP)
      target_compile_definitions(isle PRIVATE "_CRT_SECURE_NO_WARNINGS")
    endif()
  endif()
  # Visual Studio 2017 version 15.7 needs "/Zc:__cplusplus" for __cplusplus
  if (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "19.14.26428")
    target_compile_options(lego1 PRIVATE "-Zc:__cplusplus")
    if (ISLE_BUILD_APP)
      target_compile_options(isle PRIVATE "-Zc:__cplusplus")
    endif()
  endif()
endif()

if (MSVC_FOR_DECOMP)
    target_compile_definitions(lego1 PRIVATE "ENABLE_DECOMP_ASSERTS")
    if (ISLE_BUILD_APP)
        target_compile_definitions(isle PRIVATE "ENABLE_DECOMP_ASSERTS")
    endif()
endif()

if (MSVC_FOR_DECOMP)
  # These flags have been taken from the defaults for a Visual C++ 4.20 project (the compiler the
  # game was originally built with) and tweaked slightly to produce more debugging info for reccmp.
  # They ensure a recompilation that can be byte/instruction accurate to the original binaries.
  if (ISLE_BUILD_APP)
    target_compile_options(isle PRIVATE "/MT$<$<CONFIG:Debug>:d>")
  endif()
  target_compile_options(lego1 PRIVATE "/MT$<$<CONFIG:Debug>:d>")

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

  set(CMAKE_SHARED_LINKER_FLAGS "/machine:I386")
  set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "/incremental:yes /debug")
  set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "/incremental:no")
  set(CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO "/incremental:no /debug")
  set(CMAKE_SHARED_LINKER_FLAGS_MINSIZEREL "/incremental:no")

  # Older MSVC versions don't support building in parallel.
  # Force non-parallel builds of isle and lego1 by putting them in a pool with 1 available job.
  if(CMAKE_CXX_COMPILER_ID VERSION_LESS 12)
    set_property(GLOBAL PROPERTY JOB_POOLS "msvc_lego=1;msvc_lego1=1")
    set_property(TARGET isle PROPERTY JOB_POOL_COMPILE msvc_lego)
    set_property(TARGET isle PROPERTY JOB_POOL_LINK msvc_lego)
    set_property(TARGET lego1 PROPERTY JOB_POOL_COMPILE msvc_lego1)
    set_property(TARGET lego1 PROPERTY JOB_POOL_LINK msvc_lego1)
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
