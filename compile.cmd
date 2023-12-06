@echo off

%* > "%TEMP%\compile.tmp"
set error=%errorlevel%

type %TEMP%\compile.tmp | findstr /v /b "warning C4786"

exit /b %error%
