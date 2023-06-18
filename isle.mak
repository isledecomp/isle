# Microsoft Developer Studio Generated NMAKE File, Format Version 4.20
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101
# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

!IF "$(CFG)" == ""
CFG=LEGO1 - Win32 Release
!MESSAGE No configuration specified.  Defaulting to LEGO1 - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "LEGO1 - Win32 Release" && "$(CFG)" != "LEGO1 - Win32 Debug" &&\
 "$(CFG)" != "ISLE - Win32 Release" && "$(CFG)" != "ISLE - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE 
!MESSAGE NMAKE /f "isle.mak" CFG="LEGO1 - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "LEGO1 - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "LEGO1 - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "ISLE - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "ISLE - Win32 Debug" (based on "Win32 (x86) Application")
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

!IF  "$(CFG)" == "LEGO1 - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "LEGO1\Release"
# PROP BASE Intermediate_Dir "LEGO1\Release"
# PROP BASE Target_Dir "LEGO1"
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "LEGO1\Release"
# PROP Intermediate_Dir "LEGO1\Release"
# PROP Target_Dir "LEGO1"
OUTDIR=.\LEGO1\Release
INTDIR=.\LEGO1\Release

ALL : ".\Release\LEGO1.DLL"

CLEAN : 
	-@erase "$(INTDIR)\dllmain.obj"
	-@erase "$(INTDIR)\legonavcontroller.obj"
	-@erase "$(INTDIR)\legoomni.obj"
	-@erase "$(INTDIR)\mxcore.obj"
	-@erase "$(INTDIR)\mxcriticalsection.obj"
	-@erase "$(INTDIR)\vc40.pdb"
	-@erase ".\Release\LEGO1.DLL"
	-@erase ".\Release\LEGO1.EXP"
	-@erase ".\Release\LEGO1.LIB"
	-@erase ".\Release\LEGO1.PDB"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MT /W3 /GX /Zi /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /Fp"Release/LEGO1.PCH" /YX /c
CPP_PROJ=/nologo /MT /W3 /GX /Zi /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS"\
 /Fp"Release/LEGO1.PCH" /YX /Fo"$(INTDIR)/" /Fd"$(INTDIR)/" /c 
CPP_OBJS=.\LEGO1\Release/
CPP_SBRS=.\.

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

MTL=mktyplib.exe
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /win32
MTL_PROJ=/nologo /D "NDEBUG" /win32 
RSC=rc.exe
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/LEGO1.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /pdb:"Release/LEGO1.PDB" /debug /machine:I386 /out:"Release/LEGO1.DLL" /implib:"Release/LEGO1.LIB"
# SUBTRACT LINK32 /pdb:none /map
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib /nologo /subsystem:windows /dll /incremental:no\
 /pdb:"Release/LEGO1.PDB" /debug /machine:I386 /out:"Release/LEGO1.DLL"\
 /implib:"Release/LEGO1.LIB" 
LINK32_OBJS= \
	"$(INTDIR)\dllmain.obj" \
	"$(INTDIR)\legonavcontroller.obj" \
	"$(INTDIR)\legoomni.obj" \
	"$(INTDIR)\mxcore.obj" \
	"$(INTDIR)\mxcriticalsection.obj"

".\Release\LEGO1.DLL" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "LEGO1 - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "LEGO1\Debug"
# PROP BASE Intermediate_Dir "LEGO1\Debug"
# PROP BASE Target_Dir "LEGO1"
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "LEGO1\Debug"
# PROP Intermediate_Dir "LEGO1\Debug"
# PROP Target_Dir "LEGO1"
OUTDIR=.\LEGO1\Debug
INTDIR=.\LEGO1\Debug

ALL : ".\Debug\LEGO1.DLL"

CLEAN : 
	-@erase "$(INTDIR)\dllmain.obj"
	-@erase "$(INTDIR)\legonavcontroller.obj"
	-@erase "$(INTDIR)\legoomni.obj"
	-@erase "$(INTDIR)\mxcore.obj"
	-@erase "$(INTDIR)\mxcriticalsection.obj"
	-@erase "$(INTDIR)\vc40.idb"
	-@erase "$(INTDIR)\vc40.pdb"
	-@erase "$(OUTDIR)\LEGO1.exp"
	-@erase "$(OUTDIR)\LEGO1.lib"
	-@erase "$(OUTDIR)\LEGO1.pdb"
	-@erase ".\Debug\LEGO1.DLL"
	-@erase ".\Debug\LEGO1.ILK"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /Fp"Debug/LEGO1.PCH" /YX /c
CPP_PROJ=/nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS"\
 /Fp"Debug/LEGO1.PCH" /YX /Fo"$(INTDIR)/" /Fd"$(INTDIR)/" /c 
CPP_OBJS=.\LEGO1\Debug/
CPP_SBRS=.\.

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

MTL=mktyplib.exe
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /win32
MTL_PROJ=/nologo /D "_DEBUG" /win32 
RSC=rc.exe
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/LEGO1.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386 /out:"Debug/LEGO1.DLL"
# SUBTRACT LINK32 /pdb:none /map
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib /nologo /subsystem:windows /dll /incremental:yes\
 /pdb:"$(OUTDIR)/LEGO1.pdb" /debug /machine:I386 /out:"Debug/LEGO1.DLL"\
 /implib:"$(OUTDIR)/LEGO1.lib" 
LINK32_OBJS= \
	"$(INTDIR)\dllmain.obj" \
	"$(INTDIR)\legonavcontroller.obj" \
	"$(INTDIR)\legoomni.obj" \
	"$(INTDIR)\mxcore.obj" \
	"$(INTDIR)\mxcriticalsection.obj"

".\Debug\LEGO1.DLL" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "ISLE - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "ISLE\Release"
# PROP BASE Intermediate_Dir "ISLE\Release"
# PROP BASE Target_Dir "ISLE"
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "ISLE\Release"
# PROP Intermediate_Dir "ISLE\Release"
# PROP Target_Dir "ISLE"
OUTDIR=.\ISLE\Release
INTDIR=.\ISLE\Release

ALL : "LEGO1 - Win32 Release" ".\Release\ISLE.EXE"

CLEAN : 
	-@erase "$(INTDIR)\define.obj"
	-@erase "$(INTDIR)\isle.obj"
	-@erase "$(INTDIR)\isle.res"
	-@erase "$(INTDIR)\main.obj"
	-@erase "$(INTDIR)\mxomnicreateparambase.obj"
	-@erase "$(INTDIR)\vc40.pdb"
	-@erase ".\Release\ISLE.EXE"
	-@erase ".\Release\ISLE.PDB"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /W3 /GX /Zi /O2 /I "LEGO1" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /Fp"Release/ISLE.PCH" /YX /c
CPP_PROJ=/nologo /ML /W3 /GX /Zi /O2 /I "LEGO1" /D "WIN32" /D "NDEBUG" /D\
 "_WINDOWS" /Fp"Release/ISLE.PCH" /YX /Fo"$(INTDIR)/" /Fd"$(INTDIR)/" /c 
CPP_OBJS=.\ISLE\Release/
CPP_SBRS=.\.

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

MTL=mktyplib.exe
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /win32
MTL_PROJ=/nologo /D "NDEBUG" /win32 
RSC=rc.exe
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
RSC_PROJ=/l 0x409 /fo"$(INTDIR)/isle.res" /d "NDEBUG" 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/ISLE.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib winmm.lib lego1.lib dsound.lib /nologo /subsystem:windows /pdb:"Release/ISLE.PDB" /debug /machine:I386 /out:"Release/ISLE.EXE" /LIBPATH:"ISLE/ext"
# SUBTRACT LINK32 /pdb:none /map
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib winmm.lib lego1.lib dsound.lib /nologo /subsystem:windows\
 /incremental:no /pdb:"Release/ISLE.PDB" /debug /machine:I386\
 /out:"Release/ISLE.EXE" /LIBPATH:"ISLE/ext" 
LINK32_OBJS= \
	"$(INTDIR)\define.obj" \
	"$(INTDIR)\isle.obj" \
	"$(INTDIR)\isle.res" \
	"$(INTDIR)\main.obj" \
	"$(INTDIR)\mxomnicreateparambase.obj" \
	".\Release\LEGO1.LIB"

".\Release\ISLE.EXE" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "ISLE\Debug"
# PROP BASE Intermediate_Dir "ISLE\Debug"
# PROP BASE Target_Dir "ISLE"
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "ISLE\Debug"
# PROP Intermediate_Dir "ISLE\Debug"
# PROP Target_Dir "ISLE"
OUTDIR=.\ISLE\Debug
INTDIR=.\ISLE\Debug

ALL : "LEGO1 - Win32 Debug" ".\Debug\ISLE.EXE"

CLEAN : 
	-@erase "$(INTDIR)\define.obj"
	-@erase "$(INTDIR)\isle.obj"
	-@erase "$(INTDIR)\isle.res"
	-@erase "$(INTDIR)\main.obj"
	-@erase "$(INTDIR)\mxomnicreateparambase.obj"
	-@erase "$(INTDIR)\vc40.idb"
	-@erase "$(INTDIR)\vc40.pdb"
	-@erase ".\Debug\ISLE.EXE"
	-@erase ".\Debug\ISLE.ILK"
	-@erase ".\Debug\ISLE.PDB"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
# ADD BASE CPP /nologo /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /W3 /Gm /GX /Zi /Od /I "LEGO1" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /Fp"Debug/ISLE.PCH" /YX /c
CPP_PROJ=/nologo /MLd /W3 /Gm /GX /Zi /Od /I "LEGO1" /D "WIN32" /D "_DEBUG" /D\
 "_WINDOWS" /Fp"Debug/ISLE.PCH" /YX /Fo"$(INTDIR)/" /Fd"$(INTDIR)/" /c 
CPP_OBJS=.\ISLE\Debug/
CPP_SBRS=.\.

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

MTL=mktyplib.exe
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /win32
MTL_PROJ=/nologo /D "_DEBUG" /win32 
RSC=rc.exe
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
RSC_PROJ=/l 0x409 /fo"$(INTDIR)/isle.res" /d "_DEBUG" 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/ISLE.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /debug /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib winmm.lib lego1.lib dsound.lib /nologo /subsystem:windows /pdb:"Debug/ISLE.PDB" /debug /machine:I386 /out:"Debug/ISLE.EXE" /LIBPATH:"ISLE/ext"
# SUBTRACT LINK32 /pdb:none /map
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib winmm.lib lego1.lib dsound.lib /nologo /subsystem:windows\
 /incremental:yes /pdb:"Debug/ISLE.PDB" /debug /machine:I386\
 /out:"Debug/ISLE.EXE" /LIBPATH:"ISLE/ext" 
LINK32_OBJS= \
	"$(INTDIR)\define.obj" \
	"$(INTDIR)\isle.obj" \
	"$(INTDIR)\isle.res" \
	"$(INTDIR)\main.obj" \
	"$(INTDIR)\mxomnicreateparambase.obj" \
	".\LEGO1\Debug\LEGO1.lib"

".\Debug\ISLE.EXE" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 

################################################################################
# Begin Target

# Name "LEGO1 - Win32 Release"
# Name "LEGO1 - Win32 Debug"

!IF  "$(CFG)" == "LEGO1 - Win32 Release"

!ELSEIF  "$(CFG)" == "LEGO1 - Win32 Debug"

!ENDIF 

################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxcore.cpp
DEP_CPP_MXCOR=\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	

"$(INTDIR)\mxcore.obj" : $(SOURCE) $(DEP_CPP_MXCOR) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\dllmain.cpp

"$(INTDIR)\dllmain.obj" : $(SOURCE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legoomni.cpp
DEP_CPP_LEGOO=\
	".\LEGO1\legoanimationmanager.h"\
	".\LEGO1\legobuildingmanager.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legogamestate.h"\
	".\LEGO1\legoinputmanager.h"\
	".\LEGO1\legomodelpresenter.h"\
	".\LEGO1\legoomni.h"\
	".\LEGO1\legopartpresenter.h"\
	".\LEGO1\legoroi.h"\
	".\LEGO1\legovideomanager.h"\
	".\LEGO1\legoworldpresenter.h"\
	".\LEGO1\mxatomid.h"\
	".\LEGO1\mxbackgroundaudiomanager.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxdsaction.h"\
	".\LEGO1\mxdsfile.h"\
	".\LEGO1\mxdsobject.h"\
	".\LEGO1\mxomnicreateflags.h"\
	".\LEGO1\mxomnicreateparam.h"\
	".\LEGO1\mxomnicreateparambase.h"\
	".\LEGO1\mxpalette.h"\
	".\LEGO1\mxrect32.h"\
	".\LEGO1\mxresult.h"\
	".\LEGO1\mxstreamcontroller.h"\
	".\LEGO1\mxstreamer.h"\
	".\LEGO1\mxstring.h"\
	".\LEGO1\mxticklemanager.h"\
	".\LEGO1\mxtimer.h"\
	".\LEGO1\mxtransitionmanager.h"\
	".\LEGO1\mxvariabletable.h"\
	".\LEGO1\mxvideoparam.h"\
	".\LEGO1\mxvideoparamflags.h"\
	

"$(INTDIR)\legoomni.obj" : $(SOURCE) $(DEP_CPP_LEGOO) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxcriticalsection.cpp
DEP_CPP_MXCRI=\
	".\LEGO1\mxcriticalsection.h"\
	

"$(INTDIR)\mxcriticalsection.obj" : $(SOURCE) $(DEP_CPP_MXCRI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legonavcontroller.cpp
DEP_CPP_LEGON=\
	".\LEGO1\legonavcontroller.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	

"$(INTDIR)\legonavcontroller.obj" : $(SOURCE) $(DEP_CPP_LEGON) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
# End Target
################################################################################
# Begin Target

# Name "ISLE - Win32 Release"
# Name "ISLE - Win32 Debug"

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

################################################################################
# Begin Source File

SOURCE=.\ISLE\define.cpp
DEP_CPP_DEFIN=\
	".\ISLE\define.h"\
	

"$(INTDIR)\define.obj" : $(SOURCE) $(DEP_CPP_DEFIN) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ISLE\isle.cpp
DEP_CPP_ISLE_=\
	".\ISLE\define.h"\
	".\ISLE\isle.h"\
	".\ISLE\res\resource.h"\
	".\LEGO1\legoanimationmanager.h"\
	".\LEGO1\legobuildingmanager.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legogamestate.h"\
	".\LEGO1\legoinputmanager.h"\
	".\LEGO1\legomodelpresenter.h"\
	".\LEGO1\legoomni.h"\
	".\LEGO1\legopartpresenter.h"\
	".\LEGO1\legoroi.h"\
	".\LEGO1\legovideomanager.h"\
	".\LEGO1\legoworldpresenter.h"\
	".\LEGO1\mxatomid.h"\
	".\LEGO1\mxbackgroundaudiomanager.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxdirectdraw.h"\
	".\LEGO1\mxdsaction.h"\
	".\LEGO1\mxdsfile.h"\
	".\LEGO1\mxdsobject.h"\
	".\LEGO1\mxomni.h"\
	".\LEGO1\mxomnicreateflags.h"\
	".\LEGO1\mxomnicreateparam.h"\
	".\LEGO1\mxomnicreateparambase.h"\
	".\LEGO1\mxpalette.h"\
	".\LEGO1\mxrect32.h"\
	".\LEGO1\mxresult.h"\
	".\LEGO1\mxstreamcontroller.h"\
	".\LEGO1\mxstreamer.h"\
	".\LEGO1\mxstring.h"\
	".\LEGO1\mxticklemanager.h"\
	".\LEGO1\mxtimer.h"\
	".\LEGO1\mxtransitionmanager.h"\
	".\LEGO1\mxvariabletable.h"\
	".\LEGO1\mxvideoparam.h"\
	".\LEGO1\mxvideoparamflags.h"\
	

"$(INTDIR)\isle.obj" : $(SOURCE) $(DEP_CPP_ISLE_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ISLE\main.cpp
DEP_CPP_MAIN_=\
	".\ISLE\define.h"\
	".\ISLE\isle.h"\
	".\LEGO1\legoanimationmanager.h"\
	".\LEGO1\legobuildingmanager.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legogamestate.h"\
	".\LEGO1\legoinputmanager.h"\
	".\LEGO1\legomodelpresenter.h"\
	".\LEGO1\legoomni.h"\
	".\LEGO1\legopartpresenter.h"\
	".\LEGO1\legoroi.h"\
	".\LEGO1\legovideomanager.h"\
	".\LEGO1\legoworldpresenter.h"\
	".\LEGO1\mxatomid.h"\
	".\LEGO1\mxbackgroundaudiomanager.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxdsaction.h"\
	".\LEGO1\mxdsfile.h"\
	".\LEGO1\mxdsobject.h"\
	".\LEGO1\mxomnicreateflags.h"\
	".\LEGO1\mxomnicreateparam.h"\
	".\LEGO1\mxomnicreateparambase.h"\
	".\LEGO1\mxpalette.h"\
	".\LEGO1\mxrect32.h"\
	".\LEGO1\mxresult.h"\
	".\LEGO1\mxstreamcontroller.h"\
	".\LEGO1\mxstreamer.h"\
	".\LEGO1\mxstring.h"\
	".\LEGO1\mxticklemanager.h"\
	".\LEGO1\mxtimer.h"\
	".\LEGO1\mxtransitionmanager.h"\
	".\LEGO1\mxvariabletable.h"\
	".\LEGO1\mxvideoparam.h"\
	".\LEGO1\mxvideoparamflags.h"\
	

"$(INTDIR)\main.obj" : $(SOURCE) $(DEP_CPP_MAIN_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ISLE\res\isle.rc

!IF  "$(CFG)" == "ISLE - Win32 Release"


"$(INTDIR)\isle.res" : $(SOURCE) "$(INTDIR)"
   $(RSC) /l 0x409 /fo"$(INTDIR)/isle.res" /i "ISLE\res" /d "NDEBUG" $(SOURCE)


!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"


"$(INTDIR)\isle.res" : $(SOURCE) "$(INTDIR)"
   $(RSC) /l 0x409 /fo"$(INTDIR)/isle.res" /i "ISLE\res" /d "_DEBUG" $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxomnicreateparambase.cpp
DEP_CPP_MXOMN=\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxomnicreateflags.h"\
	".\LEGO1\mxomnicreateparam.h"\
	".\LEGO1\mxomnicreateparambase.h"\
	".\LEGO1\mxpalette.h"\
	".\LEGO1\mxrect32.h"\
	".\LEGO1\mxstring.h"\
	".\LEGO1\mxvariabletable.h"\
	".\LEGO1\mxvideoparam.h"\
	".\LEGO1\mxvideoparamflags.h"\
	

"$(INTDIR)\mxomnicreateparambase.obj" : $(SOURCE) $(DEP_CPP_MXOMN) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legoanimationmanager.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legobuildingmanager.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legogamestate.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legoinputmanager.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legomodelpresenter.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legoomni.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legopartpresenter.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legoroi.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legovideomanager.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legoworldpresenter.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxatomid.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxbackgroundaudiomanager.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxbitmap.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxbool.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxcore.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxdirectdraw.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxdsaction.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxdsfile.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxomni.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxomnicreateflags.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxomnicreateparam.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxomnicreateparambase.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxpalette.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxrect32.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxresult.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxstreamcontroller.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxstreamer.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxstring.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxticklemanager.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxtimer.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxtransitionmanager.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxvariabletable.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxvideoparam.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxvideoparamflags.h

!IF  "$(CFG)" == "ISLE - Win32 Release"

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Project Dependency

# Project_Dep_Name "LEGO1"

!IF  "$(CFG)" == "ISLE - Win32 Release"

"LEGO1 - Win32 Release" : 
   $(MAKE) /$(MAKEFLAGS) /F ".\isle.mak" CFG="LEGO1 - Win32 Release" 

!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"

"LEGO1 - Win32 Debug" : 
   $(MAKE) /$(MAKEFLAGS) /F ".\isle.mak" CFG="LEGO1 - Win32 Debug" 

!ENDIF 

# End Project Dependency
# End Target
# End Project
################################################################################
