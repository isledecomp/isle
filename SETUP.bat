:: SETUP FOR LAZY PEOPLE

@echo off
color a
cls

REM UAC stuff
:init
 setlocal DisableDelayedExpansion
 set cmdInvoke=1
 set winSysFolder=System32
 set "batchPath=%~dpnx0"
 rem this works also from cmd shell, other than %~0
 for %%k in (%0) do set batchName=%%~nk
 set "vbsGetPrivileges=%temp%\OEgetPriv_%batchName%.vbs"
 setlocal EnableDelayedExpansion

:checkPrivileges
  whoami /groups /nh | find "S-1-16-12288" > nul
  if '%errorlevel%' == '0' ( goto checkPrivileges2 ) else ( goto getPrivileges )

:checkPrivileges2
  net session 1>nul 2>NUL
  if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
  if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)
  ECHO.
  
  REM Very cool echo!!! Yay
  ECHO   ===========================================
  ECHO  -                                           -
  ECHO =    Invoking UAC for privilege escalation    =
  ECHO  -                                           -
  ECHO   ===========================================

  ECHO Set UAC = CreateObject^("Shell.Application"^) > "%vbsGetPrivileges%"
  ECHO args = "ELEV " >> "%vbsGetPrivileges%"
  ECHO For Each strArg in WScript.Arguments >> "%vbsGetPrivileges%"
  ECHO args = args ^& strArg ^& " "  >> "%vbsGetPrivileges%"
  ECHO Next >> "%vbsGetPrivileges%"
  
  if '%cmdInvoke%'=='1' goto InvokeCmd 

  ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%vbsGetPrivileges%"
  goto ExecElevation

:InvokeCmd
  ECHO args = "/c """ + "!batchPath!" + """ " + args >> "%vbsGetPrivileges%"
  ECHO UAC.ShellExecute "%SystemRoot%\%winSysFolder%\cmd.exe", args, "", "runas", 1 >> "%vbsGetPrivileges%"

:ExecElevation
 "%SystemRoot%\%winSysFolder%\WScript.exe" "%vbsGetPrivileges%" %*
 exit /B

:gotPrivileges
 setlocal & cd /d %~dp0
 if '%1'=='ELEV' (del "%vbsGetPrivileges%" 1>nul 2>nul  &  shift /1)

REM Sets
set PATH=%cd%
REM for /F %%A in ('echo prompt $E^| cmd') do set "ESC=%%A"
set accuracyOfLego=99%
set funnyCoolThingBuildTypeIDunno=Release
set sdkName=sdk
setx CMakeDir /k "HKEY_LOCAL_MACHINE\SOFTWARE\Kitware\CMake\InstallDir" :: Makes a variable that returns the cmake install directory
cls
goto FirstStep

REM Steps
:FirstStep
echo Welcome to the setup for compiling LEGO Island!
echo ========== Details ===========
echo -
echo = Accuracy: %accuracyOfLego%
echo = Implementation: 100%
echo -
echo ==============================
pause
cls
goto BuildTypeShi

:BuildTypeShi
REM Build Type Configuration
echo Select your build type:
echo  ======================
echo -
ECHO   1: Debug
ECHO   2: Release
ECHO   3: MinSizeRel
ECHO   4: RelWithDebInfo
echo -
echo  ======================

set /p dumbAss=
if "%dumbAss%"=="1" goto SetDebug
if "%dumbAss%"=="2" goto SetRelease
if "%dumbAss%"=="3" goto SetMinSizeRel
if "%dumbAss%"=="4" goto SetRelWithDebInfo
REM if "%dumbAss%"=="5" goto CMakeDirTest

:SetDebug
set funnyCoolThingBuildTypeIDunno=Debug
goto doneSettingShit

:CMakeDirTest
reg query "HKCU\Environment" /v "CMakeDir" :: (works)
echo on
echo FOR TESTING PURPOSES!
echo "%CMakeDir%"
pause
goto BuildTypeShi

:SetRelease
set funnyCoolThingBuildTypeIDunno=Release
goto doneSettingShit

:SetMinSizeRel
set funnyCoolThingBuildTypeIDunno=MinSizeRel
goto doneSettingShit

:SetRelWithDebInfo
set funnyCoolThingBuildTypeIDunno=RelWithDebInfo
goto doneSettingShit

:doneSettingShit
echo Done!
pause
goto dumb

REM Compiler choice
:dumb
cls
echo Enter your compiler:
echo  ====================
echo -
ECHO   1: NMake Makefiles
ECHO   2: Ninja (does not support making debug symbols)
echo -
echo  ====================
set /p bullShit=
IF "%bullShit%"=="1" GOTO NMake
IF "%bullShit%"=="2" GOTO Ninja

:NMake
cls
ECHO -- NMake Makefiles --
REM reg query "HKCU\Environment" /v "CMakeDir" :: (works)
cmake %cd% -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=%funnyCoolThingBuildTypeIDunno%
goto End

:Ninja
echo [WARNING] Only release binaries are supported!
ECHO -- Ninja --
REM reg query "HKCU\Environment" /v "CMakeDir" :: (works)
cmake %cd% -G "Ninja" -DCMAKE_BUILD_TYPE=Release
goto End

:End
echo Done!
echo To compile, change directory to build in THIS (%cd%) folder!
echo And run either "nmake" or "ninja" (If you desire to compile in Ninja, make sure you installed it!)
pause
