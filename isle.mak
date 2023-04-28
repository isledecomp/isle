# Microsoft Developer Studio Generated NMAKE File, Format Version 4.20
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101

!IF "$(CFG)" == ""
CFG=isle - Win32 Debug
!MESSAGE No configuration specified.  Defaulting to isle - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "isle - Win32 Release" && "$(CFG)" != "isle - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE 
!MESSAGE NMAKE /f "isle.mak" CFG="isle - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "isle - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "isle - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 
################################################################################
# Begin Project
# PROP Target_Last_Scanned "isle - Win32 Debug"
CPP=cl.exe
MTL=mktyplib.exe
RSC=rc.exe

!IF  "$(CFG)" == "isle - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
OUTDIR=.\Release
INTDIR=.\Release

ALL : "$(OUTDIR)\isle.exe"

CLEAN : 
	-@erase "$(INTDIR)\define.obj"
	-@erase "$(INTDIR)\isle.obj"
	-@erase "$(INTDIR)\main.obj"
	-@erase "$(OUTDIR)\isle.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
CPP_PROJ=/nologo /ML /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS"\
 /Fp"$(INTDIR)/isle.pch" /YX /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\Release/
CPP_SBRS=.\.
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /win32
MTL_PROJ=/nologo /D "NDEBUG" /win32 
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/isle.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib dsound.lib winmm.lib lib/lego1.lib /nologo /subsystem:windows /machine:I386
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib dsound.lib winmm.lib lib/lego1.lib /nologo /subsystem:windows\
 /incremental:no /pdb:"$(OUTDIR)/isle.pdb" /machine:I386\
 /out:"$(OUTDIR)/isle.exe" 
LINK32_OBJS= \
	"$(INTDIR)\define.obj" \
	"$(INTDIR)\isle.obj" \
	"$(INTDIR)\main.obj"

"$(OUTDIR)\isle.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "isle - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
OUTDIR=.\Debug
INTDIR=.\Debug

ALL : "$(OUTDIR)\isle.exe"

CLEAN : 
	-@erase "$(INTDIR)\define.obj"
	-@erase "$(INTDIR)\isle.obj"
	-@erase "$(INTDIR)\main.obj"
	-@erase "$(INTDIR)\vc40.idb"
	-@erase "$(INTDIR)\vc40.pdb"
	-@erase "$(OUTDIR)\isle.exe"
	-@erase "$(OUTDIR)\isle.ilk"
	-@erase "$(OUTDIR)\isle.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
CPP_PROJ=/nologo /MLd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS"\
 /Fp"$(INTDIR)/isle.pch" /YX /Fo"$(INTDIR)/" /Fd"$(INTDIR)/" /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.\.
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /win32
MTL_PROJ=/nologo /D "_DEBUG" /win32 
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/isle.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /debug /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib dsound.lib winmm.lib lib/lego1.lib /nologo /subsystem:windows /debug /machine:I386
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib dsound.lib winmm.lib lib/lego1.lib /nologo /subsystem:windows\
 /incremental:yes /pdb:"$(OUTDIR)/isle.pdb" /debug /machine:I386\
 /out:"$(OUTDIR)/isle.exe" 
LINK32_OBJS= \
	"$(INTDIR)\define.obj" \
	"$(INTDIR)\isle.obj" \
	"$(INTDIR)\main.obj"

"$(OUTDIR)\isle.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 

.c{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.c{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

################################################################################
# Begin Target

# Name "isle - Win32 Release"
# Name "isle - Win32 Debug"

!IF  "$(CFG)" == "isle - Win32 Release"

!ELSEIF  "$(CFG)" == "isle - Win32 Debug"

!ENDIF 

################################################################################
# Begin Source File

SOURCE=.\app\define.cpp
DEP_CPP_DEFIN=\
	".\app\define.h"\
	

"$(INTDIR)\define.obj" : $(SOURCE) $(DEP_CPP_DEFIN) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\app\isle.cpp
DEP_CPP_ISLE_=\
	".\app\define.h"\
	".\app\isle.h"\
	".\lib\define.h"\
	".\lib\legoanimationmanager.h"\
	".\lib\legobuildingmanager.h"\
	".\lib\legogamestate.h"\
	".\lib\legoinputmanager.h"\
	".\lib\legomodelpresenter.h"\
	".\lib\legoomni.h"\
	".\lib\legopartpresenter.h"\
	".\lib\legoroi.h"\
	".\lib\legovideomanager.h"\
	".\lib\legoworldpresenter.h"\
	".\lib\mxatomid.h"\
	".\lib\mxbackgroundaudiomanager.h"\
	".\lib\mxdirectdraw.h"\
	".\lib\mxdsaction.h"\
	".\lib\mxomni.h"\
	".\lib\mxomnicreateflags.h"\
	".\lib\mxomnicreateparam.h"\
	".\lib\mxpalette.h"\
	".\lib\mxrect32.h"\
	".\lib\mxstreamcontroller.h"\
	".\lib\mxstreamer.h"\
	".\lib\mxstring.h"\
	".\lib\mxticklemanager.h"\
	".\lib\mxtimer.h"\
	".\lib\mxtransitionmanager.h"\
	".\lib\mxvariabletable.h"\
	".\lib\mxvideoparam.h"\
	".\lib\mxvideoparamflags.h"\
	

"$(INTDIR)\isle.obj" : $(SOURCE) $(DEP_CPP_ISLE_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\app\main.cpp
DEP_CPP_MAIN_=\
	".\app\define.h"\
	".\app\isle.h"\
	".\lib\define.h"\
	".\lib\legoanimationmanager.h"\
	".\lib\legobuildingmanager.h"\
	".\lib\legogamestate.h"\
	".\lib\legoinputmanager.h"\
	".\lib\legomodelpresenter.h"\
	".\lib\legoomni.h"\
	".\lib\legopartpresenter.h"\
	".\lib\legoroi.h"\
	".\lib\legovideomanager.h"\
	".\lib\legoworldpresenter.h"\
	".\lib\mxatomid.h"\
	".\lib\mxbackgroundaudiomanager.h"\
	".\lib\mxdsaction.h"\
	".\lib\mxomnicreateflags.h"\
	".\lib\mxomnicreateparam.h"\
	".\lib\mxpalette.h"\
	".\lib\mxrect32.h"\
	".\lib\mxstreamcontroller.h"\
	".\lib\mxstreamer.h"\
	".\lib\mxstring.h"\
	".\lib\mxticklemanager.h"\
	".\lib\mxtimer.h"\
	".\lib\mxtransitionmanager.h"\
	".\lib\mxvariabletable.h"\
	".\lib\mxvideoparam.h"\
	".\lib\mxvideoparamflags.h"\
	

"$(INTDIR)\main.obj" : $(SOURCE) $(DEP_CPP_MAIN_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
# End Target
# End Project
################################################################################
