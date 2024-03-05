cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

# MSVC runtime library flags are selected by an abstraction
cmake_policy(SET CMP0091 NEW)

project(isle CXX)

include(CheckCXXSourceCompiles)
include(CMakeDependentOption)
include(CMakePushCheckState)

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

set(lego1_targets)
macro(register_lego1_target __target)
  list(APPEND lego1_targets ${__target})
endmacro()

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
option(ISLE_USE_SMARTHEAP "Build with SmartHeap" ${MSVC_FOR_DECOMP})
option(ISLE_USE_DX5 "Build with internal DirectX 5 SDK" ON)
cmake_dependent_option(ISLE_USE_DX5_LIBS "Build with internal DirectX 5 SDK Libraries" ON ISLE_USE_DX5 OFF)

add_cxx_warning(parentheses)

add_library(DirectX5::DirectX5 INTERFACE IMPORTED)
target_include_directories(DirectX5::DirectX5 INTERFACE "${CMAKE_SOURCE_DIR}/3rdparty/dx5/inc")
if(ISLE_USE_DX5_LIBS)
    target_link_directories(DirectX5::DirectX5 INTERFACE "${CMAKE_SOURCE_DIR}/3rdparty/dx5/lib")
endif()

add_library(Smacker::Smacker STATIC IMPORTED)
set_property(TARGET Smacker::Smacker PROPERTY IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/3rdparty/smacker/smack.lib")
set_property(TARGET Smacker::Smacker PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/3rdparty/smacker")

add_library(Vec::Vec INTERFACE IMPORTED)
target_include_directories(Vec::Vec INTERFACE "${CMAKE_SOURCE_DIR}/3rdparty/vec")

add_library(SmartHeap::SmartHeap STATIC IMPORTED)
set_property(TARGET SmartHeap::SmartHeap PROPERTY IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/3rdparty/smartheap/SHLW32MT.LIB")
set_property(TARGET SmartHeap::SmartHeap PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/3rdparty/smartheap")
set_property(TARGET SmartHeap::SmartHeap PROPERTY INTERFACE_COMPILE_OPTIONS "/FI${CMAKE_SOURCE_DIR}/3rdparty/smartheap/SMRTHEAP.HPP")

add_library(tglrl STATIC
  LEGO1/tgl/d3drm/camera.cpp
  LEGO1/tgl/d3drm/device.cpp
  LEGO1/tgl/d3drm/group.cpp
  LEGO1/tgl/d3drm/light.cpp
  LEGO1/tgl/d3drm/mesh.cpp
  LEGO1/tgl/d3drm/renderer.cpp
  LEGO1/tgl/d3drm/texture.cpp
  LEGO1/tgl/d3drm/unk.cpp
  LEGO1/tgl/d3drm/view.cpp
)
register_lego1_target(tglrl)
set_property(TARGET tglrl PROPERTY ARCHIVE_OUTPUT_NAME "tglrl40$<$<CONFIG:Debug>:d>")
target_include_directories(tglrl PRIVATE "${CMAKE_SOURCE_DIR}/LEGO1" "${CMAKE_SOURCE_DIR}/util")
target_link_libraries(tglrl PRIVATE d3drm)

add_library(realtime STATIC
  LEGO1/realtime/matrix.cpp
  LEGO1/realtime/orientableroi.cpp
  LEGO1/realtime/realtime.cpp
  LEGO1/realtime/realtimeview.cpp
  LEGO1/realtime/vector.cpp
)
register_lego1_target(realtime)
set_property(TARGET realtime PROPERTY ARCHIVE_OUTPUT_NAME "realtime$<$<CONFIG:Debug>:d>")
target_include_directories(realtime PRIVATE "${CMAKE_SOURCE_DIR}/LEGO1" "${CMAKE_SOURCE_DIR}/util")
target_link_libraries(realtime PRIVATE Vec::Vec)

add_library(viewmanager STATIC
  LEGO1/viewmanager/viewlod.cpp
  LEGO1/viewmanager/viewlodlist.cpp
  LEGO1/viewmanager/viewmanager.cpp
  LEGO1/viewmanager/viewroi.cpp
)
register_lego1_target(viewmanager)
set_property(TARGET viewmanager PROPERTY ARCHIVE_OUTPUT_NAME "viewmanager$<$<CONFIG:Debug>:d>")
target_include_directories(viewmanager PRIVATE "${CMAKE_SOURCE_DIR}/LEGO1" "${CMAKE_SOURCE_DIR}/util")
target_link_libraries(viewmanager PRIVATE Vec::Vec)

add_library(mxdirectx STATIC
  LEGO1/mxdirectx/mxdirect3d.cpp
  LEGO1/mxdirectx/mxdirectdraw.cpp
)
register_lego1_target(mxdirectx)
set_property(TARGET mxdirectx PROPERTY ARCHIVE_OUTPUT_NAME "MxDirectX$<$<CONFIG:Debug>:d>")
target_include_directories(mxdirectx PRIVATE "${CMAKE_SOURCE_DIR}/LEGO1" "${CMAKE_SOURCE_DIR}/util")
target_link_libraries(mxdirectx PRIVATE ddraw)

add_library(roi STATIC
  LEGO1/lego/sources/roi/legoroi.cpp
)
register_lego1_target(roi)
set_property(TARGET roi PROPERTY ARCHIVE_OUTPUT_NAME "roi$<$<CONFIG:Debug>:d>")
target_include_directories(roi PRIVATE "${CMAKE_SOURCE_DIR}/LEGO1/omni/include" "${CMAKE_SOURCE_DIR}/LEGO1" "${CMAKE_SOURCE_DIR}/LEGO1/lego/sources" "${CMAKE_SOURCE_DIR}/util")
target_link_libraries(roi PRIVATE viewmanager Vec::Vec)

add_library(geom STATIC
  LEGO1/lego/sources/geom/legobox.cpp
  LEGO1/lego/sources/geom/legosphere.cpp
  LEGO1/lego/sources/geom/legovertex.cpp
)
register_lego1_target(geom)
set_property(TARGET geom PROPERTY ARCHIVE_OUTPUT_NAME "geom$<$<CONFIG:Debug>:d>")
target_include_directories(geom PRIVATE "${CMAKE_SOURCE_DIR}/LEGO1/omni/include" "${CMAKE_SOURCE_DIR}/LEGO1" "${CMAKE_SOURCE_DIR}/LEGO1/lego/sources" "${CMAKE_SOURCE_DIR}/util")
target_link_libraries(geom PRIVATE)

add_library(anim STATIC
  LEGO1/lego/sources/anim/legoanim.cpp
)
register_lego1_target(anim)
set_property(TARGET anim PROPERTY ARCHIVE_OUTPUT_NAME "anim$<$<CONFIG:Debug>:d>")
target_include_directories(anim PRIVATE "${CMAKE_SOURCE_DIR}/LEGO1/omni/include" "${CMAKE_SOURCE_DIR}/LEGO1" "${CMAKE_SOURCE_DIR}/LEGO1/lego/sources" "${CMAKE_SOURCE_DIR}/util")
target_link_libraries(anim PRIVATE)

add_library(misc STATIC
  LEGO1/lego/sources/misc/legocontainer.cpp
  LEGO1/lego/sources/misc/legoimage.cpp
  LEGO1/lego/sources/misc/legostorage.cpp
  LEGO1/lego/sources/misc/legotexture.cpp
  LEGO1/lego/sources/misc/legotree.cpp
)
register_lego1_target(misc)
set_property(TARGET misc PROPERTY ARCHIVE_OUTPUT_NAME "misc$<$<CONFIG:Debug>:d>")
target_include_directories(misc PRIVATE "${CMAKE_SOURCE_DIR}/LEGO1/omni/include" "${CMAKE_SOURCE_DIR}/LEGO1" "${CMAKE_SOURCE_DIR}/LEGO1/lego/sources" "${CMAKE_SOURCE_DIR}/util")
target_link_libraries(misc PRIVATE)

add_library(3dmanager STATIC
  LEGO1/lego/sources/3dmanager/lego3dmanager.cpp
  LEGO1/lego/sources/3dmanager/lego3dview.cpp
  LEGO1/lego/sources/3dmanager/legoview1.cpp
  LEGO1/lego/sources/3dmanager/tglsurface.cpp
)
register_lego1_target(3dmanager)
set_property(TARGET 3dmanager PROPERTY ARCHIVE_OUTPUT_NAME "3dmanager$<$<CONFIG:Debug>:d>")
target_include_directories(3dmanager PRIVATE "${CMAKE_SOURCE_DIR}/LEGO1" "${CMAKE_SOURCE_DIR}/util")
target_link_libraries(3dmanager PRIVATE Vec::Vec)

add_library(omni STATIC
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
  LEGO1/omni/src/video/flic.cpp
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
)
register_lego1_target(omni)
set_property(TARGET omni PROPERTY ARCHIVE_OUTPUT_NAME "omni$<$<CONFIG:Debug>:d>")
target_include_directories(omni PRIVATE "${CMAKE_SOURCE_DIR}/LEGO1/omni/include" "${CMAKE_SOURCE_DIR}/LEGO1" "${CMAKE_SOURCE_DIR}/util")
target_link_libraries(omni PRIVATE dsound winmm Smacker::Smacker)

add_library(lego1 SHARED
  LEGO1/define.cpp
  LEGO1/lego/legoomni/src/act1/act1state.cpp
  LEGO1/lego/legoomni/src/act2/act2brick.cpp
  LEGO1/lego/legoomni/src/act2/act2policestation.cpp
  LEGO1/lego/legoomni/src/act2/legoact2.cpp
  LEGO1/lego/legoomni/src/act2/legoact2state.cpp
  LEGO1/lego/legoomni/src/act3/act3.cpp
  LEGO1/lego/legoomni/src/act3/act3shark.cpp
  LEGO1/lego/legoomni/src/act3/act3state.cpp
  LEGO1/lego/legoomni/src/audio/lego3dwavepresenter.cpp
  LEGO1/lego/legoomni/src/audio/legocachesound.cpp
  LEGO1/lego/legoomni/src/audio/legoloadcachesoundpresenter.cpp
  LEGO1/lego/legoomni/src/audio/legosoundmanager.cpp
  LEGO1/lego/legoomni/src/audio/legounknown100d5778.cpp
  LEGO1/lego/legoomni/src/audio/legounknown100d6b4c.cpp
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
  LEGO1/lego/legoomni/src/common/legoactioncontrolpresenter.cpp
  LEGO1/lego/legoomni/src/common/legobackgroundcolor.cpp
  LEGO1/lego/legoomni/src/common/legofullscreenmovie.cpp
  LEGO1/lego/legoomni/src/common/legogamestate.cpp
  LEGO1/lego/legoomni/src/common/legoobjectfactory.cpp
  LEGO1/lego/legoomni/src/common/legoplantmanager.cpp
  LEGO1/lego/legoomni/src/common/legostate.cpp
  LEGO1/lego/legoomni/src/common/legotextureinfo.cpp
  LEGO1/lego/legoomni/src/common/legounksavedatawriter.cpp
  LEGO1/lego/legoomni/src/common/legoutil.cpp
  LEGO1/lego/legoomni/src/common/legovariables.cpp
  LEGO1/lego/legoomni/src/common/mxcompositemediapresenter.cpp
  LEGO1/lego/legoomni/src/control/legocontrolmanager.cpp
  LEGO1/lego/legoomni/src/control/mxcontrolpresenter.cpp
  LEGO1/lego/legoomni/src/entity/legoactor.cpp
  LEGO1/lego/legoomni/src/entity/legoactorpresenter.cpp
  LEGO1/lego/legoomni/src/entity/legoanimactor.cpp
  LEGO1/lego/legoomni/src/entity/legocameracontroller.cpp
  LEGO1/lego/legoomni/src/entity/legocarraceactor.cpp
  LEGO1/lego/legoomni/src/entity/legoentity.cpp
  LEGO1/lego/legoomni/src/entity/legoentitypresenter.cpp
  LEGO1/lego/legoomni/src/entity/legojetski.cpp
  LEGO1/lego/legoomni/src/entity/legojetskiraceactor.cpp
  LEGO1/lego/legoomni/src/entity/legonavcontroller.cpp
  LEGO1/lego/legoomni/src/entity/legopathactor.cpp
  LEGO1/lego/legoomni/src/entity/legopovcontroller.cpp
  LEGO1/lego/legoomni/src/entity/legorace.cpp
  LEGO1/lego/legoomni/src/entity/legoraceactor.cpp
  LEGO1/lego/legoomni/src/entity/legoracecar.cpp
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
  LEGO1/lego/legoomni/src/isle/doors.cpp
  LEGO1/lego/legoomni/src/isle/historybook.cpp
  LEGO1/lego/legoomni/src/isle/isleactor.cpp
  LEGO1/lego/legoomni/src/isle/isle.cpp
  LEGO1/lego/legoomni/src/isle/islepathactor.cpp
  LEGO1/lego/legoomni/src/isle/jukebox.cpp
  LEGO1/lego/legoomni/src/isle/jukeboxentity.cpp
  LEGO1/lego/legoomni/src/isle/jukeboxstate.cpp
  LEGO1/lego/legoomni/src/isle/motocycle.cpp
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
  LEGO1/lego/legoomni/src/video/legoloopinganimpresenter.cpp
  LEGO1/lego/legoomni/src/video/legometerpresenter.cpp
  LEGO1/lego/legoomni/src/video/legomodelpresenter.cpp
  LEGO1/lego/legoomni/src/video/legopalettepresenter.cpp
  LEGO1/lego/legoomni/src/video/legopartpresenter.cpp
  LEGO1/lego/legoomni/src/video/legophonemepresenter.cpp
  LEGO1/lego/legoomni/src/video/legotexturepresenter.cpp
  LEGO1/lego/legoomni/src/video/legovideomanager.cpp
  LEGO1/lego/legoomni/src/video/mxtransitionmanager.cpp
  LEGO1/main.cpp
  LEGO1/modeldb/modeldb.cpp
)
register_lego1_target(lego1)

if (MINGW)
  target_compile_definitions(lego1 PRIVATE DIRECTINPUT_VERSION=0x0500)
endif()

if (MSVC)
  target_sources(lego1 PRIVATE LEGO1/LegoOmni.def)
else()
  target_sources(lego1 PRIVATE LEGO1/LegoOmni.mingw.def)
endif()

target_include_directories(lego1 PUBLIC "${CMAKE_SOURCE_DIR}/util")
target_include_directories(lego1 PUBLIC "${CMAKE_SOURCE_DIR}/LEGO1")
target_include_directories(lego1 PUBLIC "${CMAKE_SOURCE_DIR}/LEGO1/omni/include")
target_include_directories(lego1 PUBLIC "${CMAKE_SOURCE_DIR}/LEGO1/lego/sources")
target_include_directories(lego1 PUBLIC "${CMAKE_SOURCE_DIR}/LEGO1/lego/legoomni/include")

# Link libraries
target_link_libraries(lego1 PRIVATE tglrl viewmanager realtime mxdirectx roi geom anim Vec::Vec dinput dxguid misc 3dmanager omni)

if (ISLE_USE_SMARTHEAP)
  foreach(tgt IN LISTS lego1_targets)
    target_link_libraries(${tgt} PRIVATE SmartHeap::SmartHeap)
  endforeach()
endif()
foreach(tgt IN LISTS lego1_targets)
  target_link_libraries(${tgt} PRIVATE $<$<BOOL:${ISLE_USE_DX5}>:DirectX5::DirectX5>)
endforeach()

# Make sure filenames are ALL CAPS
set_property(TARGET lego1 PROPERTY OUTPUT_NAME LEGO1)
set_property(TARGET lego1 PROPERTY PREFIX "")
set_property(TARGET lego1 PROPERTY SUFFIX ".DLL")

if (ISLE_BUILD_APP)
  add_executable(isle WIN32
    ISLE/res/isle.rc
    ISLE/isleapp.cpp
  )

  target_compile_definitions(isle PRIVATE ISLE_APP)

  # Use internal DirectX 5 if required
  target_link_libraries(isle PRIVATE $<$<BOOL:${ISLE_USE_DX5}>:DirectX5::DirectX5>)

  if (ISLE_USE_SMARTHEAP)
    target_link_libraries(isle PRIVATE SmartHeap::SmartHeap)
  endif()

  # Link DSOUND, WINMM, and LEGO1
  target_link_libraries(isle PRIVATE dsound winmm lego1)

  # Make sure filenames are ALL CAPS
  set_property(TARGET isle PROPERTY OUTPUT_NAME ISLE)
  set_property(TARGET isle PROPERTY SUFFIX ".EXE")
endif()

if (ISLE_BUILD_CONFIG)
  add_executable(config WIN32
    LEGO1/mxdirectx/mxdirect3d.cpp
    CONFIG/config.cpp
    CONFIG/ConfigCommandLineInfo.cpp
    CONFIG/AboutDlg.cpp
    CONFIG/MainDlg.cpp
    CONFIG/detectdx5.cpp
    CONFIG/StdAfx.cpp
    CONFIG/res/config.rc
  )
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
    set_property(TARGET ${lego1_targets} APPEND PROPERTY COMPILE_DEFINITIONS "_CRT_SECURE_NO_WARNINGS")
    if (TARGET isle)
      target_compile_definitions(isle PRIVATE "_CRT_SECURE_NO_WARNINGS")
    endif()
    if (TARGET config)
      target_compile_definitions(config PRIVATE "_CRT_SECURE_NO_WARNINGS")
    endif()
  endif()
  # Visual Studio 2017 version 15.7 needs "/Zc:__cplusplus" for __cplusplus
  if (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "19.14.26428")
    foreach(tgt IN LISTS lego1_targets)
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

if (MSVC_FOR_DECOMP)
    foreach(tgt IN LISTS lego1_targets)
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

  # Equivalent to target_compile_options(... PRIVATE "/MT$<$<CONFIG:Debug>:d>")
  set_property(TARGET lego1 ${lego1_targets} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

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
    foreach(tgt IN LISTS lego1_targets)
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
