add_executable(isle WIN32
	src/define.cpp
	src/main.cpp
	src/isle.cpp
	src/res/isle.rc

	../lego1/src/mxomnicreateparambase.cpp
)

# Left for when lego1 is featured enough to be bootstrappable.
#if(ISLE_BUILD_LEGO1)
#	target_link_libraries(isle PRIVATE lego1)
#else()
	target_include_directories(isle PRIVATE ${PROJECT_SOURCE_DIR}/lego1/include)
	target_link_libraries(isle PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/ext/lego1.lib
	)
#endif()


target_include_directories(isle PRIVATE 
	${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(isle PRIVATE
	DX5::DSound
	winmm
)
