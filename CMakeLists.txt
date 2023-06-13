cmake_minimum_required(VERSION 3.10) # just for sanity's sake

project(
	isle
	LANGUAGES C CXX
)

include(${PROJECT_SOURCE_DIR}/cmake/dx5sdk.cmake)

if(ISLE_BUILD_LEGO1)
	add_subdirectory(lego1)
endif()

add_subdirectory(isle)
