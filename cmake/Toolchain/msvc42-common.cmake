# Common place for msvc42 toolchain stuff that Doesn't change

# these don't seem to actually be listened to but in the rare case they are
# set them anyways
set(MSVC_INCREMENTAL_DEFAULT OFF CACHE STRING "")
set(CMAKE_COMPILER_SUPPORTS_PDBTYPE OFF CACHE STRING "")

foreach(lang C CXX)
	set(CMAKE_${lang}_FLAGS "/DWIN32 /D_WINDOWS /W3 /Zm1000 /I$ENV{ISLE_KIT_ROOT}/msvc420/include" CACHE STRING "")
	set(CMAKE_${lang}_FLAGS_DEBUG "/MDd /Zi /Ob0 /Od" CACHE STRING "")

	set(CMAKE_${lang}_FLAGS_INIT "/DWIN32 /D_WINDOWS /W3 /Zm1000 /I$ENV{ISLE_KIT_ROOT}/msvc420/include" CACHE STRING "")
	set(CMAKE_${lang}_FLAGS_INIT_DEBUG "/MDd /Zi /Ob0 /Od" CACHE STRING "")
endforeach()

set(CMAKE_EXE_LINKER_FLAGS "/LIBPATH:$ENV{ISLE_KIT_ROOT}/msvc420/lib /incremental:no")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "/debug /incremental:no")
set(CMAKE_SHARED_LINKER_FLAGS "/LIBPATH:$ENV{ISLE_KIT_ROOT}/msvc420/lib /incremental:no")

