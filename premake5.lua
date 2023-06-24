
--require("nmake")
require("nmake2")

newoption {
	trigger     = "with-lto",
	description = "Build with link time optimization"
}

workspace "isle"
	language "C++"
	configurations { "Debug", "Release" }
	startproject "isle"
	location "build"
	symbols "Full"
	warnings "Extra"
	symbols "on"

	filter { "system:windows" }
		configurations { "Vanilla" }
		defines { "WIN32", "_WINDOWS" }
		platforms {
			"win-x86",
			"win-amd64",
			"win-arm",
			"win-arm64"
		}

	filter { "system:linux" }
		platforms {
			"linux-x86",
			"linux-amd64",
			"linux-arm",
			"linux-arm64",
		}

	filter { "system:bsd" }
		platforms {
			"bsd-x86",
			"bsd-amd64",
			"bsd-arm",
			"bsd-arm64"
		}

	filter { "system:macosx" }
		platforms {
			"macosx-arm64",
			"macosx-amd64",
		}

	filter "configurations:Debug"
		defines { "DEBUG" }

	filter "configurations:not Debug"
		defines { "NDEBUG" }
		optimize "Speed"
		if(_OPTIONS["with-lto"]) then
			flags { "LinkTimeOptimization" }
		end

	filter { "platforms:win*" }
		system "windows"

	filter { "platforms:linux*" }
		system "linux"

	filter { "platforms:bsd*" }
		system "bsd"

	filter { "platforms:macosx*" }
		system "macosx"

	filter { "platforms:*x86*" }
		architecture "x86"

	filter { "platforms:*amd64*" }
		architecture "amd64"

	filter { "platforms:*arm*" }
		architecture "ARM"
		
	filter { "platforms:*arm64*" }
		architecture "ARM64"

	filter { "platforms:macosx-arm64*", "files:**.cpp"}
		buildoptions { "-target", "arm64-apple-macos11", "-std=gnu++14" }

	filter { "platforms:macosx-arm64*", "files:**.c"}
		buildoptions { "-target", "arm64-apple-macos11" }

	filter { "platforms:macosx-amd64*", "files:**.cpp"}
		buildoptions { "-target", "x86_64-apple-macos10.12", "-std=gnu++14" }

	filter { "platforms:macosx-amd64*", "files:**.c"}
		buildoptions { "-target", "x86_64-apple-macos10.12" }

	filter  {}

local function addSrcFiles( prefix )
	return prefix .. "/*cpp", prefix .. "/*.h", prefix .. "/*.c", prefix .. "/*.ico", prefix .. "/*.rc"
end

project "isle"
	kind "WindowedApp"
	targetname "isle"
	targetdir "bin/%{cfg.platform}/%{cfg.buildcfg}"
	links { "lego1" }
	resincludedirs { "." }
	dependson { "lego1" }
	staticruntime "libc"

	--libdirs { "bin/%{cfg.platform}/%{cfg.buildcfg}" }
	
	files { addSrcFiles("ISLE") }
	files { addSrcFiles("ISLE/res") }

	includedirs { "LEGO1" }

	filter { "platforms:win*" }
		links { "dsound", "advapi32", "user32", "Gdi32", "Winmm" }
		resoptions { "/l 0x409" }
	
	filter "configurations:Vanilla"
		defines { "VANILLA_DEFINES" }
		
	filter {}
	
	
project "lego1"
	--kind "StaticLib"
	kind "SharedLib"
	targetname "lego1"
	targetdir "bin/%{cfg.platform}/%{cfg.buildcfg}"
	staticruntime "on"

	files { addSrcFiles("LEGO1") }

	filter { "platforms:win*" }
		links { "dsound", "advapi32", "user32", "Gdi32", "Winmm" }
	
	filter "configurations:Vanilla"
		defines { "VANILLA_DEFINES" }
	
	filter {}
	
