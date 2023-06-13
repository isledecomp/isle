add_library(lego1 SHARED
	src/dllmain.cpp
	
	# OMNI source
	src/mxcore.cpp
	src/mxcriticalsection.cpp
	src/mxomnicreateparambase.cpp

	# legoomni source
	src/legoomni.cpp
)

target_include_directories(lego1 PUBLIC 
	${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(lego1 PRIVATE 
	${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(lego1 PRIVATE
	DX5::DSound
	winmm
)
