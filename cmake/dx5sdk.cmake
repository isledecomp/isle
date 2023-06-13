# Make sure the user provided a valid kit root.
if("$ENV{ISLE_KIT_ROOT}" STREQUAL "")
	message(FATAL_ERROR "ISLE_KIT_ROOT needs to be set to build")
endif()


set(__DX5_SDK_PATH "$ENV{ISLE_KIT_ROOT}/dx5sdk/sdk")

# There are no seperated includes, so for nicity just define a common interface target
# that nets us includes, that all DX5 targets include from.
#  This techinically means a project can do a no-no and use, say D3D apis w/o linking D3D, 
# but that's a footgun that requires knowledge of this so I'm not particulary.. worried about it?
add_library(__DX5_Inc INTERFACE)
target_include_directories(__DX5_Inc INTERFACE ${__DX5_SDK_PATH}/inc)

# Bootstrapping problems are fun.
add_library(DX5::Guid STATIC IMPORTED)
set_property(TARGET DX5::Guid PROPERTY
		IMPORTED_LOCATION $ENV{ISLE_KIT_ROOT}/dx5sdk/sdk/lib/dxguid.lib
	)


macro(__add_dx5_lib name libname)
	add_library(DX5::${name} SHARED IMPORTED)
	target_link_libraries(DX5::${name} INTERFACE __DX5_Inc DX5::Guid)
	set_property(TARGET DX5::${name} PROPERTY
		IMPORTED_IMPLIB ${__DX5_SDK_PATH}/lib/${libname}
	)
endmacro()


__add_dx5_lib(D3DRM d3drm.lib)
__add_dx5_lib(DDraw ddraw.lib)
__add_dx5_lib(DInput dinput.lib)
__add_dx5_lib(DSound dsound.lib)

