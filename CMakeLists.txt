cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(isle CXX)

option(ISLE_BUILD_APP "Build ISLE.EXE application" ON)
option(ISLE_USE_SMARTHEAP "Build with SmartHeap" ${MSVC})
option(ISLE_USE_DX5 "Build with internal DirectX 5 SDK" ON)

add_library(lego1 SHARED
  LEGO1/act1state.cpp
  LEGO1/act2brick.cpp
  LEGO1/act2policestation.cpp
  LEGO1/act3.cpp
  LEGO1/act3shark.cpp
  LEGO1/act3state.cpp
  LEGO1/ambulance.cpp
  LEGO1/ambulancemissionstate.cpp
  LEGO1/animstate.cpp
  LEGO1/beachhouseentity.cpp
  LEGO1/bike.cpp
  LEGO1/buildingentity.cpp
  LEGO1/bumpbouy.cpp
  LEGO1/carrace.cpp
  LEGO1/define.cpp
  LEGO1/dllmain.cpp
  LEGO1/dunebuggy.cpp
  LEGO1/elevatorbottom.cpp
  LEGO1/gasstation.cpp
  LEGO1/gasstationentity.cpp
  LEGO1/gasstationstate.cpp
  LEGO1/gifmanager.cpp
  LEGO1/helicopter.cpp
  LEGO1/helicopterstate.cpp
  LEGO1/historybook.cpp
  LEGO1/hospital.cpp
  LEGO1/hospitalentity.cpp
  LEGO1/hospitalstate.cpp
  LEGO1/infocenter.cpp
  LEGO1/infocenterdoor.cpp
  LEGO1/infocenterentity.cpp
  LEGO1/infocenterstate.cpp
  LEGO1/isle.cpp
  LEGO1/isleactor.cpp
  LEGO1/islepathactor.cpp
  LEGO1/jetski.cpp
  LEGO1/jetskirace.cpp
  LEGO1/jukebox.cpp
  LEGO1/jukeboxentity.cpp
  LEGO1/jukeboxstate.cpp
  LEGO1/lego3dmanager.cpp
  LEGO1/lego3dview.cpp
  LEGO1/legoact2state.cpp
  LEGO1/legoactioncontrolpresenter.cpp
  LEGO1/legoactor.cpp
  LEGO1/legoactor.cpp
  LEGO1/legoanimactor.cpp
  LEGO1/legoanimationmanager.cpp
  LEGO1/legoanimmmpresenter.cpp
  LEGO1/legoanimpresenter.cpp
  LEGO1/legobackgroundcolor.cpp
  LEGO1/legobackgroundcolor.cpp
  LEGO1/legobuildingmanager.cpp
  LEGO1/legocachesound.cpp
  LEGO1/legocameracontroller.cpp
  LEGO1/legocarbuild.cpp
  LEGO1/legocarbuildanimpresenter.cpp
  LEGO1/legocontrolmanager.cpp
  LEGO1/legoentity.cpp
  LEGO1/legoentitypresenter.cpp
  LEGO1/legoeventnotificationparam.cpp
  LEGO1/legoflctexturepresenter.cpp
  LEGO1/legofullscreenmovie.cpp
  LEGO1/legogamestate.cpp
  LEGO1/legohideanimpresenter.cpp
  LEGO1/legoinputmanager.cpp
  LEGO1/legojetski.cpp
  LEGO1/legoloadcachesoundpresenter.cpp
  LEGO1/legolocomotionanimpresenter.cpp
  LEGO1/legometerpresenter.cpp
  LEGO1/legomodelpresenter.cpp
  LEGO1/legonavcontroller.cpp
  LEGO1/legoobjectfactory.cpp
  LEGO1/legoomni.cpp
  LEGO1/legopalettepresenter.cpp
  LEGO1/legopartpresenter.cpp
  LEGO1/legopathactor.cpp
  LEGO1/legopathcontroller.cpp
  LEGO1/legopathpresenter.cpp
  LEGO1/legophonemepresenter.cpp
  LEGO1/legoplantmanager.cpp
  LEGO1/legorace.cpp
  LEGO1/legoroi.cpp
  LEGO1/legosoundmanager.cpp
  LEGO1/legostate.cpp
  LEGO1/legostream.cpp
  LEGO1/legotexturepresenter.cpp
  LEGO1/legoutil.cpp
  LEGO1/legounksavedatawriter.cpp
  LEGO1/legovehiclebuildstate.cpp
  LEGO1/legovideomanager.cpp
  LEGO1/legoworld.cpp
  LEGO1/legoworldpresenter.cpp
  LEGO1/motorcycle.cpp
  LEGO1/mxactionnotificationparam.cpp
  LEGO1/mxatomid.cpp
  LEGO1/mxatomidcounter.cpp
  LEGO1/mxaudiomanager.cpp
  LEGO1/mxaudiopresenter.cpp
  LEGO1/mxautolocker.cpp
  LEGO1/mxbackgroundaudiomanager.cpp
  LEGO1/mxbitmap.cpp
  LEGO1/mxcompositemediapresenter.cpp
  LEGO1/mxcompositepresenter.cpp
  LEGO1/mxcontrolpresenter.cpp
  LEGO1/mxcore.cpp
  LEGO1/mxcriticalsection.cpp
  LEGO1/mxdirect3d.cpp
  LEGO1/mxdirectdraw.cpp
  LEGO1/mxdiskstreamcontroller.cpp
  LEGO1/mxdiskstreamprovider.cpp
  LEGO1/mxdisplaysurface.cpp
  LEGO1/mxdsaction.cpp
  LEGO1/mxdsanim.cpp
  LEGO1/mxdsbuffer.cpp
  LEGO1/mxdschunk.cpp
  LEGO1/mxdsevent.cpp
  LEGO1/mxdsfile.cpp
  LEGO1/mxdsmediaaction.cpp
  LEGO1/mxdsmultiaction.cpp
  LEGO1/mxdsobject.cpp
  LEGO1/mxdsobjectaction.cpp
  LEGO1/mxdsparallelaction.cpp
  LEGO1/mxdsselectaction.cpp
  LEGO1/mxdsserialaction.cpp
  LEGO1/mxdssound.cpp
  LEGO1/mxdssource.cpp
  LEGO1/mxdsstill.cpp
  LEGO1/mxdsstreamingaction.cpp
  LEGO1/mxdssubscriber.cpp
  LEGO1/mxentity.cpp
  LEGO1/mxeventmanager.cpp
  LEGO1/mxeventpresenter.cpp
  LEGO1/mxflcpresenter.cpp
  LEGO1/mxioinfo.cpp
  LEGO1/mxloopingflcpresenter.cpp
  LEGO1/mxloopingmidipresenter.cpp
  LEGO1/mxloopingsmkpresenter.cpp
  LEGO1/mxmediamanager.cpp
  LEGO1/mxmediapresenter.cpp
  LEGO1/mxmidipresenter.cpp
  LEGO1/mxmusicmanager.cpp
  LEGO1/mxmusicpresenter.cpp
  LEGO1/mxnotificationmanager.cpp
  LEGO1/mxnotificationparam.cpp
  LEGO1/mxobjectfactory.cpp
  LEGO1/mxomni.cpp
  LEGO1/mxomnicreateflags.cpp
  LEGO1/mxomnicreateparam.cpp
  LEGO1/mxpalette.cpp
  LEGO1/mxparam.cpp
  LEGO1/mxpresenter.cpp
  LEGO1/mxramstreamcontroller.cpp
  LEGO1/mxramstreamprovider.cpp
  LEGO1/mxregion.cpp
  LEGO1/mxrendersettings.cpp
  LEGO1/mxscheduler.cpp
  LEGO1/mxsemaphore.cpp
  LEGO1/mxsmack.cpp
  LEGO1/mxsmkpresenter.cpp
  LEGO1/mxsoundmanager.cpp
  LEGO1/mxsoundpresenter.cpp
  LEGO1/mxstillpresenter.cpp
  LEGO1/mxstreamchunk.cpp
  LEGO1/mxstreamcontroller.cpp
  LEGO1/mxstreamer.cpp
  LEGO1/mxstreamlist.cpp
  LEGO1/mxstreamprovider.cpp
  LEGO1/mxstring.cpp
  LEGO1/mxthread.cpp
  LEGO1/mxticklemanager.cpp
  LEGO1/mxtimer.cpp
  LEGO1/mxtransitionmanager.cpp
  LEGO1/mxtype17notificationparam.cpp
  LEGO1/mxunknown100dbdbc.cpp
  LEGO1/mxvariable.cpp
  LEGO1/mxvariabletable.cpp
  LEGO1/mxvideomanager.cpp
  LEGO1/mxvideoparam.cpp
  LEGO1/mxvideoparamflags.cpp
  LEGO1/mxvideopresenter.cpp
  LEGO1/mxwavepresenter.cpp
  LEGO1/pizza.cpp
  LEGO1/pizzamissionstate.cpp
  LEGO1/pizzeria.cpp
  LEGO1/pizzeriastate.cpp
  LEGO1/police.cpp
  LEGO1/policeentity.cpp
  LEGO1/policestate.cpp
  LEGO1/racecar.cpp
  LEGO1/racestandsentity.cpp
  LEGO1/racestate.cpp
  LEGO1/radio.cpp
  LEGO1/radiostate.cpp
  LEGO1/realtime/matrix.cpp
  LEGO1/realtime/orientableroi.cpp
  LEGO1/realtime/realtime.cpp
  LEGO1/realtime/realtimeview.cpp
  LEGO1/realtime/vector.cpp
  LEGO1/registrationbook.cpp
  LEGO1/score.cpp
  LEGO1/scorestate.cpp
  LEGO1/skateboard.cpp
  LEGO1/tgl/d3drm/camera.cpp
  LEGO1/tgl/d3drm/device.cpp
  LEGO1/tgl/d3drm/group.cpp
  LEGO1/tgl/d3drm/light.cpp
  LEGO1/tgl/d3drm/mesh.cpp
  LEGO1/tgl/d3drm/renderer.cpp
  LEGO1/tgl/d3drm/texture.cpp
  LEGO1/tgl/d3drm/unk.cpp
  LEGO1/tgl/d3drm/view.cpp
  LEGO1/towtrack.cpp
  LEGO1/towtrackmissionstate.cpp
  LEGO1/viewmanager/viewmanager.cpp
  LEGO1/viewmanager/viewroi.cpp
)
if (MINGW)
  target_compile_definitions(lego1 PRIVATE DIRECTINPUT_VERSION=0x0500)
endif()

# Additional include directories
target_include_directories(lego1 PRIVATE "${CMAKE_SOURCE_DIR}/util")
target_include_directories(lego1 PUBLIC "${CMAKE_SOURCE_DIR}/3rdparty/vec")
target_include_directories(lego1 PRIVATE "${CMAKE_SOURCE_DIR}/3rdparty/flic")
target_include_directories(lego1 PRIVATE "${CMAKE_SOURCE_DIR}/3rdparty/smack")

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

target_link_directories(lego1 PRIVATE "${CMAKE_SOURCE_DIR}/3rdparty/smack")

# Link libraries
target_link_libraries(lego1 PRIVATE ddraw dsound dxguid dinput winmm d3drm smack)

# Make sure filenames are ALL CAPS
set_property(TARGET lego1 PROPERTY OUTPUT_NAME LEGO1)
set_property(TARGET lego1 PROPERTY SUFFIX ".DLL")

if (ISLE_BUILD_APP)
  add_executable(isle WIN32
    ISLE/res/isle.rc
    ISLE/isleapp.cpp
    ISLE/define.cpp
  )

  target_include_directories(isle PRIVATE "${CMAKE_SOURCE_DIR}/util")

  # Include LEGO1 headers in ISLE
  target_include_directories(isle PRIVATE "${CMAKE_SOURCE_DIR}/LEGO1")

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
  # These flags have been taken from the defaults for a Visual C++ 4.20 project (the compiler the
  # game was originally built with) and tweaked slightly to produce more debugging info for reccmp.
  # They ensure a recompilation that can be byte/instruction accurate to the original binaries.
  if (ISLE_BUILD_APP)
    target_compile_options(isle PRIVATE "/ML$<$<CONFIG:Debug>:d>")
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
endif()
