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
	-@erase "$(INTDIR)\act2brick.obj"
	-@erase "$(INTDIR)\act3.obj"
	-@erase "$(INTDIR)\act3shark.obj"
	-@erase "$(INTDIR)\actlstate.obj"
	-@erase "$(INTDIR)\ambulance.obj"
	-@erase "$(INTDIR)\ambulancemissionstate.obj"
	-@erase "$(INTDIR)\animstate.obj"
	-@erase "$(INTDIR)\beachhouseentity.obj"
	-@erase "$(INTDIR)\bike.obj"
	-@erase "$(INTDIR)\buildingentity.obj"
	-@erase "$(INTDIR)\bumpbouy.obj"
	-@erase "$(INTDIR)\dllmain.obj"
	-@erase "$(INTDIR)\dunebuggy.obj"
	-@erase "$(INTDIR)\elevatorbottom.obj"
	-@erase "$(INTDIR)\gasstation.obj"
	-@erase "$(INTDIR)\gasstationentity.obj"
	-@erase "$(INTDIR)\gasstationstate.obj"
	-@erase "$(INTDIR)\helicopter.obj"
	-@erase "$(INTDIR)\historybook.obj"
	-@erase "$(INTDIR)\hospital.obj"
	-@erase "$(INTDIR)\hospitalentity.obj"
	-@erase "$(INTDIR)\hospitalstate.obj"
	-@erase "$(INTDIR)\infocenterdoor.obj"
	-@erase "$(INTDIR)\infocenterentity.obj"
	-@erase "$(INTDIR)\infocenterstate.obj"
	-@erase "$(INTDIR)\isle.obj"
	-@erase "$(INTDIR)\isleactor.obj"
	-@erase "$(INTDIR)\islepathactor.obj"
	-@erase "$(INTDIR)\jetski.obj"
	-@erase "$(INTDIR)\jetskiRace.obj"
	-@erase "$(INTDIR)\jukebox.obj"
	-@erase "$(INTDIR)\jukeboxentity.obj"
	-@erase "$(INTDIR)\legoactioncontrolpresenter.obj"
	-@erase "$(INTDIR)\legoanimactor.obj"
	-@erase "$(INTDIR)\legoanimationmanager.obj"
	-@erase "$(INTDIR)\legoanimmmpresenter.obj"
	-@erase "$(INTDIR)\legoanimpresenter.obj"
	-@erase "$(INTDIR)\legobuildingmanager.obj"
	-@erase "$(INTDIR)\legocachesound.obj"
	-@erase "$(INTDIR)\legocameracontroller.obj"
	-@erase "$(INTDIR)\legocarbuild.obj"
	-@erase "$(INTDIR)\legocarbuildanimpresenter.obj"
	-@erase "$(INTDIR)\legocontrolmanager.obj"
	-@erase "$(INTDIR)\legoentity.obj"
	-@erase "$(INTDIR)\legoentitypresenter.obj"
	-@erase "$(INTDIR)\legoflctexturepresenter.obj"
	-@erase "$(INTDIR)\legohideanimpresenter.obj"
	-@erase "$(INTDIR)\legojetski.obj"
	-@erase "$(INTDIR)\legoloadcachesoundpresenter.obj"
	-@erase "$(INTDIR)\legolocomotionanimpresenter.obj"
	-@erase "$(INTDIR)\legonavcontroller.obj"
	-@erase "$(INTDIR)\legoomni.obj"
	-@erase "$(INTDIR)\legopalettepresenter.obj"
	-@erase "$(INTDIR)\legopathactor.obj"
	-@erase "$(INTDIR)\legopathpresenter.obj"
	-@erase "$(INTDIR)\legophonemepresenter.obj"
	-@erase "$(INTDIR)\legoplantmanager.obj"
	-@erase "$(INTDIR)\legosoundmanager.obj"
	-@erase "$(INTDIR)\legotexturepresenter.obj"
	-@erase "$(INTDIR)\legowavepresenter.obj"
	-@erase "$(INTDIR)\legoworld.obj"
	-@erase "$(INTDIR)\legoworldpresenter.obj"
	-@erase "$(INTDIR)\motorcycle.obj"
	-@erase "$(INTDIR)\mxatomid.obj"
	-@erase "$(INTDIR)\mxautolocker.obj"
	-@erase "$(INTDIR)\mxcompositemediapresenter.obj"
	-@erase "$(INTDIR)\mxcompositepresenter.obj"
	-@erase "$(INTDIR)\mxcontrolpresenter.obj"
	-@erase "$(INTDIR)\mxcore.obj"
	-@erase "$(INTDIR)\mxcriticalsection.obj"
	-@erase "$(INTDIR)\mxdsfile.obj"
	-@erase "$(INTDIR)\mxdsobject.obj"
	-@erase "$(INTDIR)\mxentity.obj"
	-@erase "$(INTDIR)\mxeventpresenter.obj"
	-@erase "$(INTDIR)\mxflcpresenter.obj"
	-@erase "$(INTDIR)\mxloopingflxpresenter.obj"
	-@erase "$(INTDIR)\mxloopingsmkpresenter.obj"
	-@erase "$(INTDIR)\mxmediapresenter.obj"
	-@erase "$(INTDIR)\mxmusicpresenter.obj"
	-@erase "$(INTDIR)\mxomni.obj"
	-@erase "$(INTDIR)\mxomnicreateflags.obj"
	-@erase "$(INTDIR)\mxomnicreateparam.obj"
	-@erase "$(INTDIR)\mxomnicreateparambase.obj"
	-@erase "$(INTDIR)\mxpresenter.obj"
	-@erase "$(INTDIR)\mxsmkpresenter.obj"
	-@erase "$(INTDIR)\mxstillpresenter.obj"
	-@erase "$(INTDIR)\mxstring.obj"
	-@erase "$(INTDIR)\mxtimer.obj"
	-@erase "$(INTDIR)\mxtransitionmanager.obj"
	-@erase "$(INTDIR)\mxvideoparam.obj"
	-@erase "$(INTDIR)\mxvideoparamflags.obj"
	-@erase "$(INTDIR)\mxwavepresenter.obj"
	-@erase "$(INTDIR)\pizza.obj"
	-@erase "$(INTDIR)\pizzeria.obj"
	-@erase "$(INTDIR)\pizzeriastate.obj"
	-@erase "$(INTDIR)\police.obj"
	-@erase "$(INTDIR)\policeentity.obj"
	-@erase "$(INTDIR)\policestate.obj"
	-@erase "$(INTDIR)\racecar.obj"
	-@erase "$(INTDIR)\racestandsentity.obj"
	-@erase "$(INTDIR)\racestate.obj"
	-@erase "$(INTDIR)\radio.obj"
	-@erase "$(INTDIR)\radiostate.obj"
	-@erase "$(INTDIR)\registrationbook.obj"
	-@erase "$(INTDIR)\score.obj"
	-@erase "$(INTDIR)\skateboard.obj"
	-@erase "$(INTDIR)\towtrack.obj"
	-@erase "$(INTDIR)\towtrackmissionstate.obj"
	-@erase "$(INTDIR)\vc40.pdb"
	-@erase ".\Release\LEGO1.DLL"
	-@erase ".\Release\LEGO1.EXP"
	-@erase ".\Release\LEGO1.LIB"
	-@erase ".\Release\LEGO1.PDB"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MT /W3 /GX /Zi /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
CPP_PROJ=/nologo /MT /W3 /GX /Zi /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS"\
 /Fp"$(INTDIR)/LEGO1.pch" /YX /Fo"$(INTDIR)/" /Fd"$(INTDIR)/" /c 
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
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib winmm.lib /nologo /subsystem:windows /dll /pdb:"Release/LEGO1.PDB" /debug /machine:I386 /out:"Release/LEGO1.DLL" /implib:"Release/LEGO1.LIB"
# SUBTRACT LINK32 /pdb:none /map
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib winmm.lib /nologo /subsystem:windows /dll /incremental:no\
 /pdb:"Release/LEGO1.PDB" /debug /machine:I386 /out:"Release/LEGO1.DLL"\
 /implib:"Release/LEGO1.LIB" 
LINK32_OBJS= \
	"$(INTDIR)\act2brick.obj" \
	"$(INTDIR)\act3.obj" \
	"$(INTDIR)\act3shark.obj" \
	"$(INTDIR)\actlstate.obj" \
	"$(INTDIR)\ambulance.obj" \
	"$(INTDIR)\ambulancemissionstate.obj" \
	"$(INTDIR)\animstate.obj" \
	"$(INTDIR)\beachhouseentity.obj" \
	"$(INTDIR)\bike.obj" \
	"$(INTDIR)\buildingentity.obj" \
	"$(INTDIR)\bumpbouy.obj" \
	"$(INTDIR)\dllmain.obj" \
	"$(INTDIR)\dunebuggy.obj" \
	"$(INTDIR)\elevatorbottom.obj" \
	"$(INTDIR)\gasstation.obj" \
	"$(INTDIR)\gasstationentity.obj" \
	"$(INTDIR)\gasstationstate.obj" \
	"$(INTDIR)\helicopter.obj" \
	"$(INTDIR)\historybook.obj" \
	"$(INTDIR)\hospital.obj" \
	"$(INTDIR)\hospitalentity.obj" \
	"$(INTDIR)\hospitalstate.obj" \
	"$(INTDIR)\infocenterdoor.obj" \
	"$(INTDIR)\infocenterentity.obj" \
	"$(INTDIR)\infocenterstate.obj" \
	"$(INTDIR)\isle.obj" \
	"$(INTDIR)\isleactor.obj" \
	"$(INTDIR)\islepathactor.obj" \
	"$(INTDIR)\jetski.obj" \
	"$(INTDIR)\jetskiRace.obj" \
	"$(INTDIR)\jukebox.obj" \
	"$(INTDIR)\jukeboxentity.obj" \
	"$(INTDIR)\legoactioncontrolpresenter.obj" \
	"$(INTDIR)\legoanimactor.obj" \
	"$(INTDIR)\legoanimationmanager.obj" \
	"$(INTDIR)\legoanimmmpresenter.obj" \
	"$(INTDIR)\legoanimpresenter.obj" \
	"$(INTDIR)\legobuildingmanager.obj" \
	"$(INTDIR)\legocachesound.obj" \
	"$(INTDIR)\legocameracontroller.obj" \
	"$(INTDIR)\legocarbuild.obj" \
	"$(INTDIR)\legocarbuildanimpresenter.obj" \
	"$(INTDIR)\legocontrolmanager.obj" \
	"$(INTDIR)\legoentity.obj" \
	"$(INTDIR)\legoentitypresenter.obj" \
	"$(INTDIR)\legoflctexturepresenter.obj" \
	"$(INTDIR)\legohideanimpresenter.obj" \
	"$(INTDIR)\legojetski.obj" \
	"$(INTDIR)\legoloadcachesoundpresenter.obj" \
	"$(INTDIR)\legolocomotionanimpresenter.obj" \
	"$(INTDIR)\legonavcontroller.obj" \
	"$(INTDIR)\legoomni.obj" \
	"$(INTDIR)\legopalettepresenter.obj" \
	"$(INTDIR)\legopathactor.obj" \
	"$(INTDIR)\legopathpresenter.obj" \
	"$(INTDIR)\legophonemepresenter.obj" \
	"$(INTDIR)\legoplantmanager.obj" \
	"$(INTDIR)\legosoundmanager.obj" \
	"$(INTDIR)\legotexturepresenter.obj" \
	"$(INTDIR)\legowavepresenter.obj" \
	"$(INTDIR)\legoworld.obj" \
	"$(INTDIR)\legoworldpresenter.obj" \
	"$(INTDIR)\motorcycle.obj" \
	"$(INTDIR)\mxatomid.obj" \
	"$(INTDIR)\mxautolocker.obj" \
	"$(INTDIR)\mxcompositemediapresenter.obj" \
	"$(INTDIR)\mxcompositepresenter.obj" \
	"$(INTDIR)\mxcontrolpresenter.obj" \
	"$(INTDIR)\mxcore.obj" \
	"$(INTDIR)\mxcriticalsection.obj" \
	"$(INTDIR)\mxdsfile.obj" \
	"$(INTDIR)\mxdsobject.obj" \
	"$(INTDIR)\mxentity.obj" \
	"$(INTDIR)\mxeventpresenter.obj" \
	"$(INTDIR)\mxflcpresenter.obj" \
	"$(INTDIR)\mxloopingflxpresenter.obj" \
	"$(INTDIR)\mxloopingsmkpresenter.obj" \
	"$(INTDIR)\mxmediapresenter.obj" \
	"$(INTDIR)\mxmusicpresenter.obj" \
	"$(INTDIR)\mxomni.obj" \
	"$(INTDIR)\mxomnicreateflags.obj" \
	"$(INTDIR)\mxomnicreateparam.obj" \
	"$(INTDIR)\mxomnicreateparambase.obj" \
	"$(INTDIR)\mxpresenter.obj" \
	"$(INTDIR)\mxsmkpresenter.obj" \
	"$(INTDIR)\mxstillpresenter.obj" \
	"$(INTDIR)\mxstring.obj" \
	"$(INTDIR)\mxtimer.obj" \
	"$(INTDIR)\mxtransitionmanager.obj" \
	"$(INTDIR)\mxvideoparam.obj" \
	"$(INTDIR)\mxvideoparamflags.obj" \
	"$(INTDIR)\mxwavepresenter.obj" \
	"$(INTDIR)\pizza.obj" \
	"$(INTDIR)\pizzeria.obj" \
	"$(INTDIR)\pizzeriastate.obj" \
	"$(INTDIR)\police.obj" \
	"$(INTDIR)\policeentity.obj" \
	"$(INTDIR)\policestate.obj" \
	"$(INTDIR)\racecar.obj" \
	"$(INTDIR)\racestandsentity.obj" \
	"$(INTDIR)\racestate.obj" \
	"$(INTDIR)\radio.obj" \
	"$(INTDIR)\radiostate.obj" \
	"$(INTDIR)\registrationbook.obj" \
	"$(INTDIR)\score.obj" \
	"$(INTDIR)\skateboard.obj" \
	"$(INTDIR)\towtrack.obj" \
	"$(INTDIR)\towtrackmissionstate.obj"

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
	-@erase "$(INTDIR)\act2brick.obj"
	-@erase "$(INTDIR)\act3.obj"
	-@erase "$(INTDIR)\act3shark.obj"
	-@erase "$(INTDIR)\actlstate.obj"
	-@erase "$(INTDIR)\ambulance.obj"
	-@erase "$(INTDIR)\ambulancemissionstate.obj"
	-@erase "$(INTDIR)\animstate.obj"
	-@erase "$(INTDIR)\beachhouseentity.obj"
	-@erase "$(INTDIR)\bike.obj"
	-@erase "$(INTDIR)\buildingentity.obj"
	-@erase "$(INTDIR)\bumpbouy.obj"
	-@erase "$(INTDIR)\dllmain.obj"
	-@erase "$(INTDIR)\dunebuggy.obj"
	-@erase "$(INTDIR)\elevatorbottom.obj"
	-@erase "$(INTDIR)\gasstation.obj"
	-@erase "$(INTDIR)\gasstationentity.obj"
	-@erase "$(INTDIR)\gasstationstate.obj"
	-@erase "$(INTDIR)\helicopter.obj"
	-@erase "$(INTDIR)\historybook.obj"
	-@erase "$(INTDIR)\hospital.obj"
	-@erase "$(INTDIR)\hospitalentity.obj"
	-@erase "$(INTDIR)\hospitalstate.obj"
	-@erase "$(INTDIR)\infocenterdoor.obj"
	-@erase "$(INTDIR)\infocenterentity.obj"
	-@erase "$(INTDIR)\infocenterstate.obj"
	-@erase "$(INTDIR)\isle.obj"
	-@erase "$(INTDIR)\isleactor.obj"
	-@erase "$(INTDIR)\islepathactor.obj"
	-@erase "$(INTDIR)\jetski.obj"
	-@erase "$(INTDIR)\jetskiRace.obj"
	-@erase "$(INTDIR)\jukebox.obj"
	-@erase "$(INTDIR)\jukeboxentity.obj"
	-@erase "$(INTDIR)\legoactioncontrolpresenter.obj"
	-@erase "$(INTDIR)\legoanimactor.obj"
	-@erase "$(INTDIR)\legoanimationmanager.obj"
	-@erase "$(INTDIR)\legoanimmmpresenter.obj"
	-@erase "$(INTDIR)\legoanimpresenter.obj"
	-@erase "$(INTDIR)\legobuildingmanager.obj"
	-@erase "$(INTDIR)\legocachesound.obj"
	-@erase "$(INTDIR)\legocameracontroller.obj"
	-@erase "$(INTDIR)\legocarbuild.obj"
	-@erase "$(INTDIR)\legocarbuildanimpresenter.obj"
	-@erase "$(INTDIR)\legocontrolmanager.obj"
	-@erase "$(INTDIR)\legoentity.obj"
	-@erase "$(INTDIR)\legoentitypresenter.obj"
	-@erase "$(INTDIR)\legoflctexturepresenter.obj"
	-@erase "$(INTDIR)\legohideanimpresenter.obj"
	-@erase "$(INTDIR)\legojetski.obj"
	-@erase "$(INTDIR)\legoloadcachesoundpresenter.obj"
	-@erase "$(INTDIR)\legolocomotionanimpresenter.obj"
	-@erase "$(INTDIR)\legonavcontroller.obj"
	-@erase "$(INTDIR)\legoomni.obj"
	-@erase "$(INTDIR)\legopalettepresenter.obj"
	-@erase "$(INTDIR)\legopathactor.obj"
	-@erase "$(INTDIR)\legopathpresenter.obj"
	-@erase "$(INTDIR)\legophonemepresenter.obj"
	-@erase "$(INTDIR)\legoplantmanager.obj"
	-@erase "$(INTDIR)\legosoundmanager.obj"
	-@erase "$(INTDIR)\legotexturepresenter.obj"
	-@erase "$(INTDIR)\legowavepresenter.obj"
	-@erase "$(INTDIR)\legoworld.obj"
	-@erase "$(INTDIR)\legoworldpresenter.obj"
	-@erase "$(INTDIR)\motorcycle.obj"
	-@erase "$(INTDIR)\mxatomid.obj"
	-@erase "$(INTDIR)\mxautolocker.obj"
	-@erase "$(INTDIR)\mxcompositemediapresenter.obj"
	-@erase "$(INTDIR)\mxcompositepresenter.obj"
	-@erase "$(INTDIR)\mxcontrolpresenter.obj"
	-@erase "$(INTDIR)\mxcore.obj"
	-@erase "$(INTDIR)\mxcriticalsection.obj"
	-@erase "$(INTDIR)\mxdsfile.obj"
	-@erase "$(INTDIR)\mxdsobject.obj"
	-@erase "$(INTDIR)\mxentity.obj"
	-@erase "$(INTDIR)\mxeventpresenter.obj"
	-@erase "$(INTDIR)\mxflcpresenter.obj"
	-@erase "$(INTDIR)\mxloopingflxpresenter.obj"
	-@erase "$(INTDIR)\mxloopingsmkpresenter.obj"
	-@erase "$(INTDIR)\mxmediapresenter.obj"
	-@erase "$(INTDIR)\mxmusicpresenter.obj"
	-@erase "$(INTDIR)\mxomni.obj"
	-@erase "$(INTDIR)\mxomnicreateflags.obj"
	-@erase "$(INTDIR)\mxomnicreateparam.obj"
	-@erase "$(INTDIR)\mxomnicreateparambase.obj"
	-@erase "$(INTDIR)\mxpresenter.obj"
	-@erase "$(INTDIR)\mxsmkpresenter.obj"
	-@erase "$(INTDIR)\mxstillpresenter.obj"
	-@erase "$(INTDIR)\mxstring.obj"
	-@erase "$(INTDIR)\mxtimer.obj"
	-@erase "$(INTDIR)\mxtransitionmanager.obj"
	-@erase "$(INTDIR)\mxvideoparam.obj"
	-@erase "$(INTDIR)\mxvideoparamflags.obj"
	-@erase "$(INTDIR)\mxwavepresenter.obj"
	-@erase "$(INTDIR)\pizza.obj"
	-@erase "$(INTDIR)\pizzeria.obj"
	-@erase "$(INTDIR)\pizzeriastate.obj"
	-@erase "$(INTDIR)\police.obj"
	-@erase "$(INTDIR)\policeentity.obj"
	-@erase "$(INTDIR)\policestate.obj"
	-@erase "$(INTDIR)\racecar.obj"
	-@erase "$(INTDIR)\racestandsentity.obj"
	-@erase "$(INTDIR)\racestate.obj"
	-@erase "$(INTDIR)\radio.obj"
	-@erase "$(INTDIR)\radiostate.obj"
	-@erase "$(INTDIR)\registrationbook.obj"
	-@erase "$(INTDIR)\score.obj"
	-@erase "$(INTDIR)\skateboard.obj"
	-@erase "$(INTDIR)\towtrack.obj"
	-@erase "$(INTDIR)\towtrackmissionstate.obj"
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
# ADD CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
CPP_PROJ=/nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS"\
 /Fp"$(INTDIR)/LEGO1.pch" /YX /Fo"$(INTDIR)/" /Fd"$(INTDIR)/" /c 
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
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib winmm.lib /nologo /subsystem:windows /dll /debug /machine:I386 /out:"Debug/LEGO1.DLL"
# SUBTRACT LINK32 /pdb:none /map
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib winmm.lib /nologo /subsystem:windows /dll /incremental:yes\
 /pdb:"$(OUTDIR)/LEGO1.pdb" /debug /machine:I386 /out:"Debug/LEGO1.DLL"\
 /implib:"$(OUTDIR)/LEGO1.lib" 
LINK32_OBJS= \
	"$(INTDIR)\act2brick.obj" \
	"$(INTDIR)\act3.obj" \
	"$(INTDIR)\act3shark.obj" \
	"$(INTDIR)\actlstate.obj" \
	"$(INTDIR)\ambulance.obj" \
	"$(INTDIR)\ambulancemissionstate.obj" \
	"$(INTDIR)\animstate.obj" \
	"$(INTDIR)\beachhouseentity.obj" \
	"$(INTDIR)\bike.obj" \
	"$(INTDIR)\buildingentity.obj" \
	"$(INTDIR)\bumpbouy.obj" \
	"$(INTDIR)\dllmain.obj" \
	"$(INTDIR)\dunebuggy.obj" \
	"$(INTDIR)\elevatorbottom.obj" \
	"$(INTDIR)\gasstation.obj" \
	"$(INTDIR)\gasstationentity.obj" \
	"$(INTDIR)\gasstationstate.obj" \
	"$(INTDIR)\helicopter.obj" \
	"$(INTDIR)\historybook.obj" \
	"$(INTDIR)\hospital.obj" \
	"$(INTDIR)\hospitalentity.obj" \
	"$(INTDIR)\hospitalstate.obj" \
	"$(INTDIR)\infocenterdoor.obj" \
	"$(INTDIR)\infocenterentity.obj" \
	"$(INTDIR)\infocenterstate.obj" \
	"$(INTDIR)\isle.obj" \
	"$(INTDIR)\isleactor.obj" \
	"$(INTDIR)\islepathactor.obj" \
	"$(INTDIR)\jetski.obj" \
	"$(INTDIR)\jetskiRace.obj" \
	"$(INTDIR)\jukebox.obj" \
	"$(INTDIR)\jukeboxentity.obj" \
	"$(INTDIR)\legoactioncontrolpresenter.obj" \
	"$(INTDIR)\legoanimactor.obj" \
	"$(INTDIR)\legoanimationmanager.obj" \
	"$(INTDIR)\legoanimmmpresenter.obj" \
	"$(INTDIR)\legoanimpresenter.obj" \
	"$(INTDIR)\legobuildingmanager.obj" \
	"$(INTDIR)\legocachesound.obj" \
	"$(INTDIR)\legocameracontroller.obj" \
	"$(INTDIR)\legocarbuild.obj" \
	"$(INTDIR)\legocarbuildanimpresenter.obj" \
	"$(INTDIR)\legocontrolmanager.obj" \
	"$(INTDIR)\legoentity.obj" \
	"$(INTDIR)\legoentitypresenter.obj" \
	"$(INTDIR)\legoflctexturepresenter.obj" \
	"$(INTDIR)\legohideanimpresenter.obj" \
	"$(INTDIR)\legojetski.obj" \
	"$(INTDIR)\legoloadcachesoundpresenter.obj" \
	"$(INTDIR)\legolocomotionanimpresenter.obj" \
	"$(INTDIR)\legonavcontroller.obj" \
	"$(INTDIR)\legoomni.obj" \
	"$(INTDIR)\legopalettepresenter.obj" \
	"$(INTDIR)\legopathactor.obj" \
	"$(INTDIR)\legopathpresenter.obj" \
	"$(INTDIR)\legophonemepresenter.obj" \
	"$(INTDIR)\legoplantmanager.obj" \
	"$(INTDIR)\legosoundmanager.obj" \
	"$(INTDIR)\legotexturepresenter.obj" \
	"$(INTDIR)\legowavepresenter.obj" \
	"$(INTDIR)\legoworld.obj" \
	"$(INTDIR)\legoworldpresenter.obj" \
	"$(INTDIR)\motorcycle.obj" \
	"$(INTDIR)\mxatomid.obj" \
	"$(INTDIR)\mxautolocker.obj" \
	"$(INTDIR)\mxcompositemediapresenter.obj" \
	"$(INTDIR)\mxcompositepresenter.obj" \
	"$(INTDIR)\mxcontrolpresenter.obj" \
	"$(INTDIR)\mxcore.obj" \
	"$(INTDIR)\mxcriticalsection.obj" \
	"$(INTDIR)\mxdsfile.obj" \
	"$(INTDIR)\mxdsobject.obj" \
	"$(INTDIR)\mxentity.obj" \
	"$(INTDIR)\mxeventpresenter.obj" \
	"$(INTDIR)\mxflcpresenter.obj" \
	"$(INTDIR)\mxloopingflxpresenter.obj" \
	"$(INTDIR)\mxloopingsmkpresenter.obj" \
	"$(INTDIR)\mxmediapresenter.obj" \
	"$(INTDIR)\mxmusicpresenter.obj" \
	"$(INTDIR)\mxomni.obj" \
	"$(INTDIR)\mxomnicreateflags.obj" \
	"$(INTDIR)\mxomnicreateparam.obj" \
	"$(INTDIR)\mxomnicreateparambase.obj" \
	"$(INTDIR)\mxpresenter.obj" \
	"$(INTDIR)\mxsmkpresenter.obj" \
	"$(INTDIR)\mxstillpresenter.obj" \
	"$(INTDIR)\mxstring.obj" \
	"$(INTDIR)\mxtimer.obj" \
	"$(INTDIR)\mxtransitionmanager.obj" \
	"$(INTDIR)\mxvideoparam.obj" \
	"$(INTDIR)\mxvideoparamflags.obj" \
	"$(INTDIR)\mxwavepresenter.obj" \
	"$(INTDIR)\pizza.obj" \
	"$(INTDIR)\pizzeria.obj" \
	"$(INTDIR)\pizzeriastate.obj" \
	"$(INTDIR)\police.obj" \
	"$(INTDIR)\policeentity.obj" \
	"$(INTDIR)\policestate.obj" \
	"$(INTDIR)\racecar.obj" \
	"$(INTDIR)\racestandsentity.obj" \
	"$(INTDIR)\racestate.obj" \
	"$(INTDIR)\radio.obj" \
	"$(INTDIR)\radiostate.obj" \
	"$(INTDIR)\registrationbook.obj" \
	"$(INTDIR)\score.obj" \
	"$(INTDIR)\skateboard.obj" \
	"$(INTDIR)\towtrack.obj" \
	"$(INTDIR)\towtrackmissionstate.obj"

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
	-@erase "$(INTDIR)\vc40.pdb"
	-@erase ".\Release\ISLE.EXE"
	-@erase ".\Release\ISLE.PDB"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /W3 /GX /Zi /O2 /I "LEGO1" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
CPP_PROJ=/nologo /ML /W3 /GX /Zi /O2 /I "LEGO1" /D "WIN32" /D "NDEBUG" /D\
 "_WINDOWS" /Fp"$(INTDIR)/ISLE.pch" /YX /Fo"$(INTDIR)/" /Fd"$(INTDIR)/" /c 
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
# SUBTRACT LINK32 /pdb:none
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
	-@erase "$(INTDIR)\vc40.idb"
	-@erase "$(INTDIR)\vc40.pdb"
	-@erase ".\Debug\ISLE.EXE"
	-@erase ".\Debug\ISLE.ILK"
	-@erase ".\Debug\ISLE.PDB"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
# ADD BASE CPP /nologo /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /W3 /Gm /GX /Zi /Od /I "LEGO1" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
CPP_PROJ=/nologo /MLd /W3 /Gm /GX /Zi /Od /I "LEGO1" /D "WIN32" /D "_DEBUG" /D\
 "_WINDOWS" /Fp"$(INTDIR)/ISLE.pch" /YX /Fo"$(INTDIR)/" /Fd"$(INTDIR)/" /c 
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
# SUBTRACT LINK32 /pdb:none
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
DEP_CPP_DLLMA=\
	".\LEGO1\legoinc.h"\
	

"$(INTDIR)\dllmain.obj" : $(SOURCE) $(DEP_CPP_DLLMA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legoomni.cpp
DEP_CPP_LEGOO=\
	".\LEGO1\isle.h"\
	".\LEGO1\lego3dmanager.h"\
	".\LEGO1\lego3dview.h"\
	".\LEGO1\legobuildingmanager.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legogamestate.h"\
	".\LEGO1\legoinc.h"\
	".\LEGO1\legoinputmanager.h"\
	".\LEGO1\legonavcontroller.h"\
	".\LEGO1\legoomni.h"\
	".\LEGO1\legoplantmanager.h"\
	".\LEGO1\legoroi.h"\
	".\LEGO1\legovideomanager.h"\
	".\LEGO1\legoworld.h"\
	".\LEGO1\mxatomid.h"\
	".\LEGO1\mxbackgroundaudiomanager.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxcriticalsection.h"\
	".\LEGO1\mxdsaction.h"\
	".\LEGO1\mxdsfile.h"\
	".\LEGO1\mxdsobject.h"\
	".\LEGO1\mxdssource.h"\
	".\LEGO1\mxentity.h"\
	".\LEGO1\mxeventmanager.h"\
	".\LEGO1\mxmusicmanager.h"\
	".\LEGO1\mxnotificationmanager.h"\
	".\LEGO1\mxobjectfactory.h"\
	".\LEGO1\mxomni.h"\
	".\LEGO1\mxomnicreateflags.h"\
	".\LEGO1\mxomnicreateparam.h"\
	".\LEGO1\mxomnicreateparambase.h"\
	".\LEGO1\mxpalette.h"\
	".\LEGO1\mxrect32.h"\
	".\LEGO1\mxresult.h"\
	".\LEGO1\mxsoundmanager.h"\
	".\LEGO1\mxstreamcontroller.h"\
	".\LEGO1\mxstreamer.h"\
	".\LEGO1\mxstring.h"\
	".\LEGO1\mxticklemanager.h"\
	".\LEGO1\mxtimer.h"\
	".\LEGO1\mxtransitionmanager.h"\
	".\LEGO1\mxvariabletable.h"\
	".\LEGO1\mxvideomanager.h"\
	".\LEGO1\mxvideoparam.h"\
	".\LEGO1\mxvideoparamflags.h"\
	".\LEGO1\viewmanager.h"\
	

"$(INTDIR)\legoomni.obj" : $(SOURCE) $(DEP_CPP_LEGOO) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxcriticalsection.cpp
DEP_CPP_MXCRI=\
	".\LEGO1\legoinc.h"\
	".\LEGO1\mxcriticalsection.h"\
	

"$(INTDIR)\mxcriticalsection.obj" : $(SOURCE) $(DEP_CPP_MXCRI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxautolocker.cpp
DEP_CPP_MXAUT=\
	".\LEGO1\legoinc.h"\
	".\LEGO1\mxautolocker.h"\
	".\LEGO1\mxcriticalsection.h"\
	

"$(INTDIR)\mxautolocker.obj" : $(SOURCE) $(DEP_CPP_MXAUT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxtimer.cpp
DEP_CPP_MXTIM=\
	".\LEGO1\legoinc.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxtimer.h"\
	

"$(INTDIR)\mxtimer.obj" : $(SOURCE) $(DEP_CPP_MXTIM) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxomni.cpp
DEP_CPP_MXOMN=\
	".\LEGO1\legoinc.h"\
	".\LEGO1\mxatomid.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxcriticalsection.h"\
	".\LEGO1\mxeventmanager.h"\
	".\LEGO1\mxmusicmanager.h"\
	".\LEGO1\mxnotificationmanager.h"\
	".\LEGO1\mxobjectfactory.h"\
	".\LEGO1\mxomni.h"\
	".\LEGO1\mxomnicreateflags.h"\
	".\LEGO1\mxomnicreateparam.h"\
	".\LEGO1\mxomnicreateparambase.h"\
	".\LEGO1\mxpalette.h"\
	".\LEGO1\mxrect32.h"\
	".\LEGO1\mxresult.h"\
	".\LEGO1\mxsoundmanager.h"\
	".\LEGO1\mxstreamcontroller.h"\
	".\LEGO1\mxstreamer.h"\
	".\LEGO1\mxstring.h"\
	".\LEGO1\mxticklemanager.h"\
	".\LEGO1\mxtimer.h"\
	".\LEGO1\mxvariabletable.h"\
	".\LEGO1\mxvideomanager.h"\
	".\LEGO1\mxvideoparam.h"\
	".\LEGO1\mxvideoparamflags.h"\
	

"$(INTDIR)\mxomni.obj" : $(SOURCE) $(DEP_CPP_MXOMN) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxvideoparam.cpp
DEP_CPP_MXVID=\
	".\LEGO1\legoinc.h"\
	".\LEGO1\mxpalette.h"\
	".\LEGO1\mxrect32.h"\
	".\LEGO1\mxvariabletable.h"\
	".\LEGO1\mxvideoparam.h"\
	".\LEGO1\mxvideoparamflags.h"\
	

"$(INTDIR)\mxvideoparam.obj" : $(SOURCE) $(DEP_CPP_MXVID) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxvideoparamflags.cpp
DEP_CPP_MXVIDE=\
	".\LEGO1\legoinc.h"\
	".\LEGO1\mxvideoparamflags.h"\
	

"$(INTDIR)\mxvideoparamflags.obj" : $(SOURCE) $(DEP_CPP_MXVIDE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxomnicreateparam.cpp
DEP_CPP_MXOMNI=\
	".\LEGO1\legoinc.h"\
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
	

"$(INTDIR)\mxomnicreateparam.obj" : $(SOURCE) $(DEP_CPP_MXOMNI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxomnicreateparambase.cpp
DEP_CPP_MXOMNIC=\
	".\LEGO1\legoinc.h"\
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
	

"$(INTDIR)\mxomnicreateparambase.obj" : $(SOURCE) $(DEP_CPP_MXOMNIC)\
 "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxstring.cpp
DEP_CPP_MXSTR=\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxstring.h"\
	

"$(INTDIR)\mxstring.obj" : $(SOURCE) $(DEP_CPP_MXSTR) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxomnicreateflags.cpp
DEP_CPP_MXOMNICR=\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxomnicreateflags.h"\
	

"$(INTDIR)\mxomnicreateflags.obj" : $(SOURCE) $(DEP_CPP_MXOMNICR) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legonavcontroller.cpp
DEP_CPP_LEGON=\
	".\LEGO1\isle.h"\
	".\LEGO1\lego3dmanager.h"\
	".\LEGO1\lego3dview.h"\
	".\LEGO1\legobuildingmanager.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legogamestate.h"\
	".\LEGO1\legoinc.h"\
	".\LEGO1\legoinputmanager.h"\
	".\LEGO1\legonavcontroller.h"\
	".\LEGO1\legoomni.h"\
	".\LEGO1\legoplantmanager.h"\
	".\LEGO1\legoroi.h"\
	".\LEGO1\legoutil.h"\
	".\LEGO1\legovideomanager.h"\
	".\LEGO1\legoworld.h"\
	".\LEGO1\mxatomid.h"\
	".\LEGO1\mxbackgroundaudiomanager.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxcriticalsection.h"\
	".\LEGO1\mxdsaction.h"\
	".\LEGO1\mxdsfile.h"\
	".\LEGO1\mxdsobject.h"\
	".\LEGO1\mxdssource.h"\
	".\LEGO1\mxentity.h"\
	".\LEGO1\mxeventmanager.h"\
	".\LEGO1\mxmusicmanager.h"\
	".\LEGO1\mxnotificationmanager.h"\
	".\LEGO1\mxobjectfactory.h"\
	".\LEGO1\mxomni.h"\
	".\LEGO1\mxomnicreateflags.h"\
	".\LEGO1\mxomnicreateparam.h"\
	".\LEGO1\mxomnicreateparambase.h"\
	".\LEGO1\mxpalette.h"\
	".\LEGO1\mxrect32.h"\
	".\LEGO1\mxresult.h"\
	".\LEGO1\mxsoundmanager.h"\
	".\LEGO1\mxstreamcontroller.h"\
	".\LEGO1\mxstreamer.h"\
	".\LEGO1\mxstring.h"\
	".\LEGO1\mxticklemanager.h"\
	".\LEGO1\mxtimer.h"\
	".\LEGO1\mxtransitionmanager.h"\
	".\LEGO1\mxvariabletable.h"\
	".\LEGO1\mxvideomanager.h"\
	".\LEGO1\mxvideoparam.h"\
	".\LEGO1\mxvideoparamflags.h"\
	".\LEGO1\viewmanager.h"\
	

"$(INTDIR)\legonavcontroller.obj" : $(SOURCE) $(DEP_CPP_LEGON) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxdsobject.cpp
DEP_CPP_MXDSO=\
	".\LEGO1\mxatomid.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxdsobject.h"\
	

"$(INTDIR)\mxdsobject.obj" : $(SOURCE) $(DEP_CPP_MXDSO) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxatomid.cpp
DEP_CPP_MXATO=\
	".\LEGO1\mxatomid.h"\
	

"$(INTDIR)\mxatomid.obj" : $(SOURCE) $(DEP_CPP_MXATO) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\infocenterdoor.cpp
DEP_CPP_INFOC=\
	".\LEGO1\infocenterdoor.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legoworld.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\infocenterdoor.obj" : $(SOURCE) $(DEP_CPP_INFOC) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legoentity.cpp
DEP_CPP_LEGOE=\
	".\LEGO1\legoentity.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\legoentity.obj" : $(SOURCE) $(DEP_CPP_LEGOE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legoworld.cpp
DEP_CPP_LEGOW=\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legoworld.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\legoworld.obj" : $(SOURCE) $(DEP_CPP_LEGOW) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxloopingsmkpresenter.cpp
DEP_CPP_MXLOO=\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxloopingsmkpresenter.h"\
	".\LEGO1\mxmediapresenter.h"\
	".\LEGO1\mxpresenter.h"\
	".\LEGO1\mxsmkpresenter.h"\
	".\LEGO1\mxvideopresenter.h"\
	

"$(INTDIR)\mxloopingsmkpresenter.obj" : $(SOURCE) $(DEP_CPP_MXLOO) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxmediapresenter.cpp
DEP_CPP_MXMED=\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxmediapresenter.h"\
	".\LEGO1\mxpresenter.h"\
	

"$(INTDIR)\mxmediapresenter.obj" : $(SOURCE) $(DEP_CPP_MXMED) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxmusicpresenter.cpp
DEP_CPP_MXMUS=\
	".\LEGO1\mxaudiopresenter.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxmediapresenter.h"\
	".\LEGO1\mxmusicpresenter.h"\
	".\LEGO1\mxpresenter.h"\
	

"$(INTDIR)\mxmusicpresenter.obj" : $(SOURCE) $(DEP_CPP_MXMUS) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxpresenter.cpp
DEP_CPP_MXPRE=\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxpresenter.h"\
	

"$(INTDIR)\mxpresenter.obj" : $(SOURCE) $(DEP_CPP_MXPRE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxsmkpresenter.cpp
DEP_CPP_MXSMK=\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxmediapresenter.h"\
	".\LEGO1\mxpresenter.h"\
	".\LEGO1\mxsmkpresenter.h"\
	".\LEGO1\mxvideopresenter.h"\
	

"$(INTDIR)\mxsmkpresenter.obj" : $(SOURCE) $(DEP_CPP_MXSMK) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxstillpresenter.cpp
DEP_CPP_MXSTI=\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxmediapresenter.h"\
	".\LEGO1\mxpresenter.h"\
	".\LEGO1\mxstillpresenter.h"\
	".\LEGO1\mxvideopresenter.h"\
	

"$(INTDIR)\mxstillpresenter.obj" : $(SOURCE) $(DEP_CPP_MXSTI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxtransitionmanager.cpp
DEP_CPP_MXTRA=\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxtransitionmanager.h"\
	

"$(INTDIR)\mxtransitionmanager.obj" : $(SOURCE) $(DEP_CPP_MXTRA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxwavepresenter.cpp
DEP_CPP_MXWAV=\
	".\LEGO1\mxaudiopresenter.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxmediapresenter.h"\
	".\LEGO1\mxpresenter.h"\
	".\LEGO1\mxsoundpresenter.h"\
	".\LEGO1\mxwavepresenter.h"\
	

"$(INTDIR)\mxwavepresenter.obj" : $(SOURCE) $(DEP_CPP_MXWAV) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\pizza.cpp
DEP_CPP_PIZZA=\
	".\LEGO1\isleactor.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	".\LEGO1\pizza.h"\
	

"$(INTDIR)\pizza.obj" : $(SOURCE) $(DEP_CPP_PIZZA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\pizzeria.cpp
DEP_CPP_PIZZE=\
	".\LEGO1\isleactor.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	".\LEGO1\pizzeria.h"\
	

"$(INTDIR)\pizzeria.obj" : $(SOURCE) $(DEP_CPP_PIZZE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\pizzeriastate.cpp
DEP_CPP_PIZZER=\
	".\LEGO1\legostate.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\pizzeriastate.h"\
	

"$(INTDIR)\pizzeriastate.obj" : $(SOURCE) $(DEP_CPP_PIZZER) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\police.cpp
DEP_CPP_POLIC=\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legoworld.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	".\LEGO1\police.h"\
	

"$(INTDIR)\police.obj" : $(SOURCE) $(DEP_CPP_POLIC) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\policeentity.cpp
DEP_CPP_POLICE=\
	".\LEGO1\buildingentity.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	".\LEGO1\policeentity.h"\
	

"$(INTDIR)\policeentity.obj" : $(SOURCE) $(DEP_CPP_POLICE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\policestate.cpp
DEP_CPP_POLICES=\
	".\LEGO1\legostate.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\policestate.h"\
	

"$(INTDIR)\policestate.obj" : $(SOURCE) $(DEP_CPP_POLICES) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\racecar.cpp
DEP_CPP_RACEC=\
	".\LEGO1\islepathactor.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legopathactor.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	".\LEGO1\racecar.h"\
	

"$(INTDIR)\racecar.obj" : $(SOURCE) $(DEP_CPP_RACEC) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\racestandsentity.cpp
DEP_CPP_RACES=\
	".\LEGO1\buildingentity.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	".\LEGO1\racestandsentity.h"\
	

"$(INTDIR)\racestandsentity.obj" : $(SOURCE) $(DEP_CPP_RACES) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\racestate.cpp
DEP_CPP_RACEST=\
	".\LEGO1\legostate.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\racestate.h"\
	

"$(INTDIR)\racestate.obj" : $(SOURCE) $(DEP_CPP_RACEST) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\radio.cpp
DEP_CPP_RADIO=\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\radio.h"\
	

"$(INTDIR)\radio.obj" : $(SOURCE) $(DEP_CPP_RADIO) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\radiostate.cpp
DEP_CPP_RADIOS=\
	".\LEGO1\legostate.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\radiostate.h"\
	

"$(INTDIR)\radiostate.obj" : $(SOURCE) $(DEP_CPP_RADIOS) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\registrationbook.cpp
DEP_CPP_REGIS=\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legoworld.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	".\LEGO1\registrationbook.h"\
	

"$(INTDIR)\registrationbook.obj" : $(SOURCE) $(DEP_CPP_REGIS) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\score.cpp
DEP_CPP_SCORE=\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legoworld.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	".\LEGO1\score.h"\
	

"$(INTDIR)\score.obj" : $(SOURCE) $(DEP_CPP_SCORE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\skateboard.cpp
DEP_CPP_SKATE=\
	".\LEGO1\islepathactor.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legopathactor.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	".\LEGO1\skateboard.h"\
	

"$(INTDIR)\skateboard.obj" : $(SOURCE) $(DEP_CPP_SKATE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\towtrack.cpp
DEP_CPP_TOWTR=\
	".\LEGO1\islepathactor.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legopathactor.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	".\LEGO1\towtrack.h"\
	

"$(INTDIR)\towtrack.obj" : $(SOURCE) $(DEP_CPP_TOWTR) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\towtrackmissionstate.cpp
DEP_CPP_TOWTRA=\
	".\LEGO1\legostate.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\towtrackmissionstate.h"\
	

"$(INTDIR)\towtrackmissionstate.obj" : $(SOURCE) $(DEP_CPP_TOWTRA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\act2brick.cpp
DEP_CPP_ACT2B=\
	".\LEGO1\act2brick.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legopathactor.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\act2brick.obj" : $(SOURCE) $(DEP_CPP_ACT2B) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\act3.cpp
DEP_CPP_ACT3_=\
	".\LEGO1\act3.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legoworld.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\act3.obj" : $(SOURCE) $(DEP_CPP_ACT3_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\act3shark.cpp
DEP_CPP_ACT3S=\
	".\LEGO1\act3shark.h"\
	".\LEGO1\legoanimactor.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legopathactor.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\act3shark.obj" : $(SOURCE) $(DEP_CPP_ACT3S) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\actlstate.cpp
DEP_CPP_ACTLS=\
	".\LEGO1\actlstate.h"\
	".\LEGO1\legostate.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	

"$(INTDIR)\actlstate.obj" : $(SOURCE) $(DEP_CPP_ACTLS) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\ambulance.cpp
DEP_CPP_AMBUL=\
	".\LEGO1\ambulance.h"\
	".\LEGO1\islepathactor.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legopathactor.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\ambulance.obj" : $(SOURCE) $(DEP_CPP_AMBUL) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\ambulancemissionstate.cpp
DEP_CPP_AMBULA=\
	".\LEGO1\ambulancemissionstate.h"\
	".\LEGO1\legostate.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	

"$(INTDIR)\ambulancemissionstate.obj" : $(SOURCE) $(DEP_CPP_AMBULA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\animstate.cpp
DEP_CPP_ANIMS=\
	".\LEGO1\animstate.h"\
	".\LEGO1\legostate.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	

"$(INTDIR)\animstate.obj" : $(SOURCE) $(DEP_CPP_ANIMS) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\beachhouseentity.cpp
DEP_CPP_BEACH=\
	".\LEGO1\beachhouseentity.h"\
	".\LEGO1\buildingentity.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\beachhouseentity.obj" : $(SOURCE) $(DEP_CPP_BEACH) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\bike.cpp
DEP_CPP_BIKE_=\
	".\LEGO1\bike.h"\
	".\LEGO1\islepathactor.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legopathactor.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\bike.obj" : $(SOURCE) $(DEP_CPP_BIKE_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\buildingentity.cpp
DEP_CPP_BUILD=\
	".\LEGO1\buildingentity.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\buildingentity.obj" : $(SOURCE) $(DEP_CPP_BUILD) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\bumpbouy.cpp
DEP_CPP_BUMPB=\
	".\LEGO1\bumpbouy.h"\
	".\LEGO1\mxbool.h"\
	

"$(INTDIR)\bumpbouy.obj" : $(SOURCE) $(DEP_CPP_BUMPB) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\dunebuggy.cpp
DEP_CPP_DUNEB=\
	".\LEGO1\dunebuggy.h"\
	".\LEGO1\islepathactor.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legopathactor.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\dunebuggy.obj" : $(SOURCE) $(DEP_CPP_DUNEB) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\elevatorbottom.cpp
DEP_CPP_ELEVA=\
	".\LEGO1\elevatorbottom.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legoworld.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\elevatorbottom.obj" : $(SOURCE) $(DEP_CPP_ELEVA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\gasstation.cpp
DEP_CPP_GASST=\
	".\LEGO1\gasstation.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legoworld.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\gasstation.obj" : $(SOURCE) $(DEP_CPP_GASST) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\gasstationentity.cpp
DEP_CPP_GASSTA=\
	".\LEGO1\buildingentity.h"\
	".\LEGO1\gasstationentity.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\gasstationentity.obj" : $(SOURCE) $(DEP_CPP_GASSTA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\gasstationstate.cpp
DEP_CPP_GASSTAT=\
	".\LEGO1\gasstationstate.h"\
	".\LEGO1\legostate.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	

"$(INTDIR)\gasstationstate.obj" : $(SOURCE) $(DEP_CPP_GASSTAT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\helicopter.cpp
DEP_CPP_HELIC=\
	".\LEGO1\helicopter.h"\
	".\LEGO1\islepathactor.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legopathactor.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\helicopter.obj" : $(SOURCE) $(DEP_CPP_HELIC) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\historybook.cpp
DEP_CPP_HISTO=\
	".\LEGO1\historybook.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legoworld.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\historybook.obj" : $(SOURCE) $(DEP_CPP_HISTO) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\hospital.cpp
DEP_CPP_HOSPI=\
	".\LEGO1\hospital.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legoworld.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\hospital.obj" : $(SOURCE) $(DEP_CPP_HOSPI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\hospitalentity.cpp
DEP_CPP_HOSPIT=\
	".\LEGO1\buildingentity.h"\
	".\LEGO1\hospitalentity.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\hospitalentity.obj" : $(SOURCE) $(DEP_CPP_HOSPIT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\hospitalstate.cpp
DEP_CPP_HOSPITA=\
	".\LEGO1\hospitalstate.h"\
	".\LEGO1\legostate.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	

"$(INTDIR)\hospitalstate.obj" : $(SOURCE) $(DEP_CPP_HOSPITA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\infocenterentity.cpp
DEP_CPP_INFOCE=\
	".\LEGO1\infocenterentity.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\infocenterentity.obj" : $(SOURCE) $(DEP_CPP_INFOCE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\infocenterstate.cpp
DEP_CPP_INFOCEN=\
	".\LEGO1\infocenterstate.h"\
	".\LEGO1\legostate.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	

"$(INTDIR)\infocenterstate.obj" : $(SOURCE) $(DEP_CPP_INFOCEN) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\isle.cpp
DEP_CPP_ISLE_=\
	".\LEGO1\isle.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legoworld.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\isle.obj" : $(SOURCE) $(DEP_CPP_ISLE_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\isleactor.cpp
DEP_CPP_ISLEA=\
	".\LEGO1\isleactor.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\isleactor.obj" : $(SOURCE) $(DEP_CPP_ISLEA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\islepathactor.cpp
DEP_CPP_ISLEP=\
	".\LEGO1\islepathactor.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legopathactor.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\islepathactor.obj" : $(SOURCE) $(DEP_CPP_ISLEP) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\jetski.cpp
DEP_CPP_JETSK=\
	".\LEGO1\islepathactor.h"\
	".\LEGO1\jetski.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legopathactor.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\jetski.obj" : $(SOURCE) $(DEP_CPP_JETSK) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\jetskiRace.cpp
DEP_CPP_JETSKI=\
	".\LEGO1\jetskiRace.h"\
	".\LEGO1\legorace.h"\
	

"$(INTDIR)\jetskiRace.obj" : $(SOURCE) $(DEP_CPP_JETSKI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\jukebox.cpp
DEP_CPP_JUKEB=\
	".\LEGO1\jukebox.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\jukebox.obj" : $(SOURCE) $(DEP_CPP_JUKEB) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\jukeboxentity.cpp
DEP_CPP_JUKEBO=\
	".\LEGO1\jukeboxentity.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\jukeboxentity.obj" : $(SOURCE) $(DEP_CPP_JUKEBO) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legoactioncontrolpresenter.cpp
DEP_CPP_LEGOA=\
	".\LEGO1\legoactioncontrolpresenter.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxmediapresenter.h"\
	".\LEGO1\mxpresenter.h"\
	

"$(INTDIR)\legoactioncontrolpresenter.obj" : $(SOURCE) $(DEP_CPP_LEGOA)\
 "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legoanimactor.cpp
DEP_CPP_LEGOAN=\
	".\LEGO1\legoanimactor.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legopathactor.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\legoanimactor.obj" : $(SOURCE) $(DEP_CPP_LEGOAN) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legoanimationmanager.cpp
DEP_CPP_LEGOANI=\
	".\LEGO1\legoanimationmanager.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	

"$(INTDIR)\legoanimationmanager.obj" : $(SOURCE) $(DEP_CPP_LEGOANI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legoanimmmpresenter.cpp
DEP_CPP_LEGOANIM=\
	".\LEGO1\legoanimmmpresenter.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcompositepresenter.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxpresenter.h"\
	

"$(INTDIR)\legoanimmmpresenter.obj" : $(SOURCE) $(DEP_CPP_LEGOANIM) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legoanimpresenter.cpp
DEP_CPP_LEGOANIMP=\
	".\LEGO1\legoanimpresenter.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxmediapresenter.h"\
	".\LEGO1\mxpresenter.h"\
	".\LEGO1\mxvideopresenter.h"\
	

"$(INTDIR)\legoanimpresenter.obj" : $(SOURCE) $(DEP_CPP_LEGOANIMP) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legobuildingmanager.cpp
DEP_CPP_LEGOB=\
	".\LEGO1\legobuildingmanager.h"\
	

"$(INTDIR)\legobuildingmanager.obj" : $(SOURCE) $(DEP_CPP_LEGOB) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legocachesound.cpp
DEP_CPP_LEGOC=\
	".\LEGO1\legocachesound.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	

"$(INTDIR)\legocachesound.obj" : $(SOURCE) $(DEP_CPP_LEGOC) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legocameracontroller.cpp
DEP_CPP_LEGOCA=\
	".\LEGO1\legocameracontroller.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	

"$(INTDIR)\legocameracontroller.obj" : $(SOURCE) $(DEP_CPP_LEGOCA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legocarbuild.cpp
DEP_CPP_LEGOCAR=\
	".\LEGO1\legocarbuild.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legoworld.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\legocarbuild.obj" : $(SOURCE) $(DEP_CPP_LEGOCAR) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legocarbuildanimpresenter.cpp
DEP_CPP_LEGOCARB=\
	".\LEGO1\legoanimpresenter.h"\
	".\LEGO1\legocarbuildanimpresenter.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxmediapresenter.h"\
	".\LEGO1\mxpresenter.h"\
	".\LEGO1\mxvideopresenter.h"\
	

"$(INTDIR)\legocarbuildanimpresenter.obj" : $(SOURCE) $(DEP_CPP_LEGOCARB)\
 "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legocontrolmanager.cpp
DEP_CPP_LEGOCO=\
	".\LEGO1\legocontrolmanager.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	

"$(INTDIR)\legocontrolmanager.obj" : $(SOURCE) $(DEP_CPP_LEGOCO) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legoentitypresenter.cpp
DEP_CPP_LEGOEN=\
	".\LEGO1\legoentitypresenter.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcompositepresenter.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxpresenter.h"\
	

"$(INTDIR)\legoentitypresenter.obj" : $(SOURCE) $(DEP_CPP_LEGOEN) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legoflctexturepresenter.cpp
DEP_CPP_LEGOF=\
	".\LEGO1\legoflctexturepresenter.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxflcpresenter.h"\
	".\LEGO1\mxmediapresenter.h"\
	".\LEGO1\mxpresenter.h"\
	".\LEGO1\mxvideopresenter.h"\
	

"$(INTDIR)\legoflctexturepresenter.obj" : $(SOURCE) $(DEP_CPP_LEGOF)\
 "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legohideanimpresenter.cpp
DEP_CPP_LEGOH=\
	".\LEGO1\legoanimpresenter.h"\
	".\LEGO1\legohideanimpresenter.h"\
	".\LEGO1\legoloopinganimpresenter.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxmediapresenter.h"\
	".\LEGO1\mxpresenter.h"\
	".\LEGO1\mxvideopresenter.h"\
	

"$(INTDIR)\legohideanimpresenter.obj" : $(SOURCE) $(DEP_CPP_LEGOH) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legojetski.cpp
DEP_CPP_LEGOJ=\
	".\LEGO1\legoanimactor.h"\
	".\LEGO1\legocarraceactor.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legojetski.h"\
	".\LEGO1\legojetskiraceactor.h"\
	".\LEGO1\legopathactor.h"\
	".\LEGO1\legoraceactor.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\legojetski.obj" : $(SOURCE) $(DEP_CPP_LEGOJ) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legoloadcachesoundpresenter.cpp
DEP_CPP_LEGOL=\
	".\LEGO1\legoloadcachesoundpresenter.h"\
	".\LEGO1\mxaudiopresenter.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxmediapresenter.h"\
	".\LEGO1\mxpresenter.h"\
	".\LEGO1\mxsoundpresenter.h"\
	".\LEGO1\mxwavepresenter.h"\
	

"$(INTDIR)\legoloadcachesoundpresenter.obj" : $(SOURCE) $(DEP_CPP_LEGOL)\
 "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legolocomotionanimpresenter.cpp
DEP_CPP_LEGOLO=\
	".\LEGO1\legoanimpresenter.h"\
	".\LEGO1\legolocomotionanimpresenter.h"\
	".\LEGO1\legoloopinganimpresenter.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxmediapresenter.h"\
	".\LEGO1\mxpresenter.h"\
	".\LEGO1\mxvideopresenter.h"\
	

"$(INTDIR)\legolocomotionanimpresenter.obj" : $(SOURCE) $(DEP_CPP_LEGOLO)\
 "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legopalettepresenter.cpp
DEP_CPP_LEGOP=\
	".\LEGO1\legopalettepresenter.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxmediapresenter.h"\
	".\LEGO1\mxpresenter.h"\
	".\LEGO1\mxvideopresenter.h"\
	

"$(INTDIR)\legopalettepresenter.obj" : $(SOURCE) $(DEP_CPP_LEGOP) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legopathactor.cpp
DEP_CPP_LEGOPA=\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legopathactor.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\legopathactor.obj" : $(SOURCE) $(DEP_CPP_LEGOPA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legopathpresenter.cpp
DEP_CPP_LEGOPAT=\
	".\LEGO1\legopathpresenter.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxmediapresenter.h"\
	".\LEGO1\mxpresenter.h"\
	

"$(INTDIR)\legopathpresenter.obj" : $(SOURCE) $(DEP_CPP_LEGOPAT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legophonemepresenter.cpp
DEP_CPP_LEGOPH=\
	".\LEGO1\legophonemepresenter.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxflcpresenter.h"\
	".\LEGO1\mxmediapresenter.h"\
	".\LEGO1\mxpresenter.h"\
	".\LEGO1\mxvideopresenter.h"\
	

"$(INTDIR)\legophonemepresenter.obj" : $(SOURCE) $(DEP_CPP_LEGOPH) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legoplantmanager.cpp
DEP_CPP_LEGOPL=\
	".\LEGO1\legoplantmanager.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	

"$(INTDIR)\legoplantmanager.obj" : $(SOURCE) $(DEP_CPP_LEGOPL) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legosoundmanager.cpp
DEP_CPP_LEGOS=\
	".\LEGO1\legosoundmanager.h"\
	".\LEGO1\mxsoundmanager.h"\
	

"$(INTDIR)\legosoundmanager.obj" : $(SOURCE) $(DEP_CPP_LEGOS) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legotexturepresenter.cpp
DEP_CPP_LEGOT=\
	".\LEGO1\legotexturepresenter.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxmediapresenter.h"\
	".\LEGO1\mxpresenter.h"\
	

"$(INTDIR)\legotexturepresenter.obj" : $(SOURCE) $(DEP_CPP_LEGOT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legowavepresenter.cpp
DEP_CPP_LEGOWA=\
	".\LEGO1\legowavepresenter.h"\
	".\LEGO1\mxaudiopresenter.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxmediapresenter.h"\
	".\LEGO1\mxpresenter.h"\
	".\LEGO1\mxsoundpresenter.h"\
	

"$(INTDIR)\legowavepresenter.obj" : $(SOURCE) $(DEP_CPP_LEGOWA) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\legoworldpresenter.cpp
DEP_CPP_LEGOWO=\
	".\LEGO1\legoentitypresenter.h"\
	".\LEGO1\legoworldpresenter.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcompositepresenter.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxpresenter.h"\
	

"$(INTDIR)\legoworldpresenter.obj" : $(SOURCE) $(DEP_CPP_LEGOWO) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\motorcycle.cpp
DEP_CPP_MOTOR=\
	".\LEGO1\islepathactor.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legopathactor.h"\
	".\LEGO1\motorcycle.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\motorcycle.obj" : $(SOURCE) $(DEP_CPP_MOTOR) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxcompositemediapresenter.cpp
DEP_CPP_MXCOM=\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcompositemediapresenter.h"\
	".\LEGO1\mxcompositepresenter.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxpresenter.h"\
	

"$(INTDIR)\mxcompositemediapresenter.obj" : $(SOURCE) $(DEP_CPP_MXCOM)\
 "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxcompositepresenter.cpp
DEP_CPP_MXCOMP=\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcompositepresenter.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxpresenter.h"\
	

"$(INTDIR)\mxcompositepresenter.obj" : $(SOURCE) $(DEP_CPP_MXCOMP) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxcontrolpresenter.cpp
DEP_CPP_MXCON=\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcompositepresenter.h"\
	".\LEGO1\mxcontrolpresenter.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxpresenter.h"\
	

"$(INTDIR)\mxcontrolpresenter.obj" : $(SOURCE) $(DEP_CPP_MXCON) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxentity.cpp
DEP_CPP_MXENT=\
	".\LEGO1\mxatomid.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxentity.h"\
	

"$(INTDIR)\mxentity.obj" : $(SOURCE) $(DEP_CPP_MXENT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxeventpresenter.cpp
DEP_CPP_MXEVE=\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxeventpresenter.h"\
	".\LEGO1\mxmediapresenter.h"\
	".\LEGO1\mxpresenter.h"\
	

"$(INTDIR)\mxeventpresenter.obj" : $(SOURCE) $(DEP_CPP_MXEVE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxflcpresenter.cpp
DEP_CPP_MXFLC=\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxflcpresenter.h"\
	".\LEGO1\mxmediapresenter.h"\
	".\LEGO1\mxpresenter.h"\
	".\LEGO1\mxvideopresenter.h"\
	

"$(INTDIR)\mxflcpresenter.obj" : $(SOURCE) $(DEP_CPP_MXFLC) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxloopingflxpresenter.cpp
DEP_CPP_MXLOOP=\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxflcpresenter.h"\
	".\LEGO1\mxloopingflxpresenter.h"\
	".\LEGO1\mxmediapresenter.h"\
	".\LEGO1\mxpresenter.h"\
	".\LEGO1\mxvideopresenter.h"\
	

"$(INTDIR)\mxloopingflxpresenter.obj" : $(SOURCE) $(DEP_CPP_MXLOOP) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\LEGO1\mxdsfile.cpp
DEP_CPP_MXDSF=\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxdsfile.h"\
	".\LEGO1\mxdssource.h"\
	

"$(INTDIR)\mxdsfile.obj" : $(SOURCE) $(DEP_CPP_MXDSF) "$(INTDIR)"
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
	".\LEGO1\legoinc.h"\
	

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
	".\LEGO1\isle.h"\
	".\LEGO1\lego3dmanager.h"\
	".\LEGO1\lego3dview.h"\
	".\LEGO1\legoanimationmanager.h"\
	".\LEGO1\legobuildingmanager.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legoentitypresenter.h"\
	".\LEGO1\legogamestate.h"\
	".\LEGO1\legoinc.h"\
	".\LEGO1\legoinputmanager.h"\
	".\LEGO1\legomodelpresenter.h"\
	".\LEGO1\legonavcontroller.h"\
	".\LEGO1\legoomni.h"\
	".\LEGO1\legopartpresenter.h"\
	".\LEGO1\legoplantmanager.h"\
	".\LEGO1\legoroi.h"\
	".\LEGO1\legovideomanager.h"\
	".\LEGO1\legoworld.h"\
	".\LEGO1\legoworldpresenter.h"\
	".\LEGO1\mxatomid.h"\
	".\LEGO1\mxbackgroundaudiomanager.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcompositepresenter.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxcriticalsection.h"\
	".\LEGO1\mxdirectdraw.h"\
	".\LEGO1\mxdsaction.h"\
	".\LEGO1\mxdsfile.h"\
	".\LEGO1\mxdsobject.h"\
	".\LEGO1\mxdssource.h"\
	".\LEGO1\mxentity.h"\
	".\LEGO1\mxeventmanager.h"\
	".\LEGO1\mxmusicmanager.h"\
	".\LEGO1\mxnotificationmanager.h"\
	".\LEGO1\mxobjectfactory.h"\
	".\LEGO1\mxomni.h"\
	".\LEGO1\mxomnicreateflags.h"\
	".\LEGO1\mxomnicreateparam.h"\
	".\LEGO1\mxomnicreateparambase.h"\
	".\LEGO1\mxpalette.h"\
	".\LEGO1\mxpresenter.h"\
	".\LEGO1\mxrect32.h"\
	".\LEGO1\mxresult.h"\
	".\LEGO1\mxsoundmanager.h"\
	".\LEGO1\mxstreamcontroller.h"\
	".\LEGO1\mxstreamer.h"\
	".\LEGO1\mxstring.h"\
	".\LEGO1\mxticklemanager.h"\
	".\LEGO1\mxtimer.h"\
	".\LEGO1\mxtransitionmanager.h"\
	".\LEGO1\mxvariabletable.h"\
	".\LEGO1\mxvideomanager.h"\
	".\LEGO1\mxvideoparam.h"\
	".\LEGO1\mxvideoparamflags.h"\
	".\LEGO1\viewmanager.h"\
	

"$(INTDIR)\isle.obj" : $(SOURCE) $(DEP_CPP_ISLE_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ISLE\main.cpp
DEP_CPP_MAIN_=\
	".\ISLE\define.h"\
	".\ISLE\isle.h"\
	".\LEGO1\isle.h"\
	".\LEGO1\lego3dmanager.h"\
	".\LEGO1\lego3dview.h"\
	".\LEGO1\legobuildingmanager.h"\
	".\LEGO1\legoentity.h"\
	".\LEGO1\legogamestate.h"\
	".\LEGO1\legoinc.h"\
	".\LEGO1\legoinputmanager.h"\
	".\LEGO1\legonavcontroller.h"\
	".\LEGO1\legoomni.h"\
	".\LEGO1\legoplantmanager.h"\
	".\LEGO1\legoroi.h"\
	".\LEGO1\legovideomanager.h"\
	".\LEGO1\legoworld.h"\
	".\LEGO1\mxatomid.h"\
	".\LEGO1\mxbackgroundaudiomanager.h"\
	".\LEGO1\mxbool.h"\
	".\LEGO1\mxcore.h"\
	".\LEGO1\mxcriticalsection.h"\
	".\LEGO1\mxdsaction.h"\
	".\LEGO1\mxdsfile.h"\
	".\LEGO1\mxdsobject.h"\
	".\LEGO1\mxdssource.h"\
	".\LEGO1\mxentity.h"\
	".\LEGO1\mxeventmanager.h"\
	".\LEGO1\mxmusicmanager.h"\
	".\LEGO1\mxnotificationmanager.h"\
	".\LEGO1\mxobjectfactory.h"\
	".\LEGO1\mxomni.h"\
	".\LEGO1\mxomnicreateflags.h"\
	".\LEGO1\mxomnicreateparam.h"\
	".\LEGO1\mxomnicreateparambase.h"\
	".\LEGO1\mxpalette.h"\
	".\LEGO1\mxrect32.h"\
	".\LEGO1\mxresult.h"\
	".\LEGO1\mxsoundmanager.h"\
	".\LEGO1\mxstreamcontroller.h"\
	".\LEGO1\mxstreamer.h"\
	".\LEGO1\mxstring.h"\
	".\LEGO1\mxticklemanager.h"\
	".\LEGO1\mxtimer.h"\
	".\LEGO1\mxtransitionmanager.h"\
	".\LEGO1\mxvariabletable.h"\
	".\LEGO1\mxvideomanager.h"\
	".\LEGO1\mxvideoparam.h"\
	".\LEGO1\mxvideoparamflags.h"\
	".\LEGO1\viewmanager.h"\
	

"$(INTDIR)\main.obj" : $(SOURCE) $(DEP_CPP_MAIN_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ISLE\res\isle.rc
DEP_RSC_ISLE_R=\
	".\ISLE\res\resource.h"\
	

!IF  "$(CFG)" == "ISLE - Win32 Release"


"$(INTDIR)\isle.res" : $(SOURCE) $(DEP_RSC_ISLE_R) "$(INTDIR)"
   $(RSC) /l 0x409 /fo"$(INTDIR)/isle.res" /i "ISLE\res" /d "NDEBUG" $(SOURCE)


!ELSEIF  "$(CFG)" == "ISLE - Win32 Debug"


"$(INTDIR)\isle.res" : $(SOURCE) $(DEP_RSC_ISLE_R) "$(INTDIR)"
   $(RSC) /l 0x409 /fo"$(INTDIR)/isle.res" /i "ISLE\res" /d "_DEBUG" $(SOURCE)


!ENDIF 

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
