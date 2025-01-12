diff --git a/CMakeLists.txt b/CMakeLists.txt
index 4f995f33..0e60ee50 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -64,7 +64,12 @@ option(ISLE_USE_SMARTHEAP "Build LEGO1.DLL with SmartHeap" ${MSVC_FOR_DECOMP})
 option(ISLE_USE_DX5 "Build with internal DirectX 5 SDK" ON)
 option(ISLE_DECOMP_ASSERT "Assert struct size" ${MSVC_FOR_DECOMP})
 cmake_dependent_option(ISLE_USE_DX5_LIBS "Build with internal DirectX 5 SDK Libraries" ON ISLE_USE_DX5 OFF)
-option(ISLE_BUILD_BETA10 "Build BETA10.EXE library" OFF)
+option(ISLE_BUILD_LEGO1 "Build LEGO1.DLL library" ON)
+option(ISLE_BUILD_BETA10 "Build BETA10.DLL library" OFF)
+
+if(NOT (ISLE_BUILD_LEGO1 OR ISLE_BUILD_BETA10))
+  message(FATAL_ERROR "ISLE_BUILD_LEGO1 AND ISLE_BUILD_BETA10 cannot be both disabled")
+endif()
 
 add_cxx_warning(parentheses)
 
@@ -460,14 +465,16 @@ if (ISLE_USE_SMARTHEAP)
   list(APPEND lego1_link_libraries SmartHeap::SmartHeap)
 endif()
 
-add_lego_libraries(lego1
-  LINK_LIBRARIES ${lego1_link_libraries}
-  DLL_OUTPUT_NAME "LEGO1"
-  DLL_PREFIX ""
-  DLL_SUFFIX ".DLL"
-  OUT_TARGETS lego1_targets
-)
-reccmp_add_target(lego1 ID LEGO1)
+if(ISLE_BUILD_LEGO1)
+  add_lego_libraries(lego1
+    LINK_LIBRARIES ${lego1_link_libraries}
+    DLL_OUTPUT_NAME "LEGO1"
+    DLL_PREFIX ""
+    DLL_SUFFIX ".DLL"
+    OUT_TARGETS lego1_targets
+  )
+  reccmp_add_target(lego1 ID LEGO1)
+endif()
 
 if(ISLE_BUILD_BETA10)
   add_lego_libraries(beta10
@@ -497,7 +504,12 @@ if (ISLE_BUILD_APP)
   endif()
 
   # Link DSOUND, WINMM, and LEGO1
-  target_link_libraries(isle PRIVATE dsound winmm lego1)
+  target_link_libraries(isle PRIVATE dsound winmm)
+  if(ISLE_BUILD_LEGO1)
+    target_link_libraries(isle PRIVATE lego1)
+  else()
+    target_link_libraries(isle PRIVATE beta10)
+  endif()
 
   # Make sure filenames are ALL CAPS
   set_property(TARGET isle PROPERTY OUTPUT_NAME ISLE)
@@ -576,10 +588,12 @@ if (MSVC_FOR_DECOMP)
     set_property(TARGET isle ${lego1_targets} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
   endif()
 
-  target_link_options(lego1 PRIVATE "/OPT:REF")
+  if(TARGET lego1)
+    target_link_options(lego1 PRIVATE "/OPT:REF")
 
-  # Equivalent to target_compile_options(... PRIVATE "/MT$<$<CONFIG:Debug>:d>")
-  set_property(TARGET lego1 ${lego1_targets} ${beta10_targets} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
+    # Equivalent to target_compile_options(... PRIVATE "/MT$<$<CONFIG:Debug>:d>")
+    set_property(TARGET lego1 ${lego1_targets} ${beta10_targets} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
+  endif()
 
   set(CMAKE_CXX_FLAGS "/W3 /GX /D \"WIN32\" /D \"_WINDOWS\"")
   set(CMAKE_CXX_FLAGS_DEBUG "/Gm /Zi /Od /D \"_DEBUG\"")
