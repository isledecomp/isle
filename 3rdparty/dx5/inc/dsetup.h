/*==========================================================================
 *
 *  Copyright (C) 1995-1997 Microsoft Corporation.  All Rights Reserved.
 *
 *  File:       dsetup.h
 *  Content:    DirectXSetup, error codes and flags
 ***************************************************************************/

#ifndef __DSETUP_H__
#define __DSETUP_H__

#include <windows.h>      // windows stuff

#ifdef _WIN32
#define COM_NO_WINDOWS_H
#include <objbase.h>
#else
#endif


#ifdef __cplusplus
extern "C" {
#endif

// DSETUP Error Codes, must remain compatible with previous setup.
#define DSETUPERR_SUCCESS_RESTART        1
#define DSETUPERR_SUCCESS                0
#define DSETUPERR_BADWINDOWSVERSION     -1
#define DSETUPERR_SOURCEFILENOTFOUND    -2
#define DSETUPERR_BADSOURCESIZE         -3
#define DSETUPERR_BADSOURCETIME         -4
#define DSETUPERR_NOCOPY                -5
#define DSETUPERR_OUTOFDISKSPACE        -6
#define DSETUPERR_CANTFINDINF           -7
#define DSETUPERR_CANTFINDDIR           -8
#define DSETUPERR_INTERNAL              -9
#define DSETUPERR_NTWITHNO3D            -10  /* REM: obsolete, you'll never see this */
#define DSETUPERR_UNKNOWNOS             -11
#define DSETUPERR_USERHITCANCEL         -12
#define DSETUPERR_NOTPREINSTALLEDONNT   -13

// DSETUP flags. DirectX 5.0 apps should use these flags only.
#define DSETUP_DDRAWDRV         0x00000008      /* install DirectDraw Drivers           */
#define DSETUP_DSOUNDDRV        0x00000010      /* install DirectSound Drivers          */
#define DSETUP_DXCORE           0x00010000	/* install DirectX runtime              */
#define DSETUP_DIRECTX  (DSETUP_DXCORE|DSETUP_DDRAWDRV|DSETUP_DSOUNDDRV)
#define DSETUP_TESTINSTALL      0x00020000      /* just test install, don't do anything */

// These OBSOLETE flags are here for compatibility with pre-DX5 apps only.
// They are present to allow DX3 apps to be recompiled with DX5 and still work.
// DO NOT USE THEM for DX5. They will go away in future DX releases.
#define DSETUP_DDRAW            0x00000001      /* OBSOLETE. install DirectDraw           */
#define DSETUP_DSOUND           0x00000002      /* OBSOLETE. install DirectSound          */
#define DSETUP_DPLAY            0x00000004      /* OBSOLETE. install DirectPlay           */
#define DSETUP_DPLAYSP          0x00000020      /* OBSOLETE. install DirectPlay Providers */
#define DSETUP_DVIDEO           0x00000040      /* OBSOLETE. install DirectVideo          */
#define DSETUP_D3D              0x00000200      /* OBSOLETE. install Direct3D             */
#define DSETUP_DINPUT           0x00000800      /* OBSOLETE. install DirectInput          */
#define DSETUP_DIRECTXSETUP     0x00001000      /* OBSOLETE. install DirectXSetup DLL's   */
#define DSETUP_NOUI             0x00002000      /* OBSOLETE. install DirectX with NO UI   */
#define DSETUP_PROMPTFORDRIVERS 0x10000000      /* OBSOLETE. prompt when replacing display/audio drivers */
#define DSETUP_RESTOREDRIVERS   0x20000000      /* OBSOLETE. restore display/audio drivers */



//******************************************************************
// DirectX Setup Callback mechanism
//******************************************************************

// DSETUP Message Info Codes, passed to callback as Reason parameter.
#define DSETUP_CB_MSG_NOMESSAGE                     0
#define DSETUP_CB_MSG_CANTINSTALL_UNKNOWNOS         1
#define DSETUP_CB_MSG_CANTINSTALL_NT                2
#define DSETUP_CB_MSG_CANTINSTALL_BETA              3
#define DSETUP_CB_MSG_CANTINSTALL_NOTWIN32          4
#define DSETUP_CB_MSG_CANTINSTALL_WRONGLANGUAGE     5
#define DSETUP_CB_MSG_CANTINSTALL_WRONGPLATFORM     6
#define DSETUP_CB_MSG_PREINSTALL_NT                 7
#define DSETUP_CB_MSG_NOTPREINSTALLEDONNT           8
#define DSETUP_CB_MSG_SETUP_INIT_FAILED             9
#define DSETUP_CB_MSG_INTERNAL_ERROR                10
#define DSETUP_CB_MSG_CHECK_DRIVER_UPGRADE          11
#define DSETUP_CB_MSG_OUTOFDISKSPACE                12
#define DSETUP_CB_MSG_BEGIN_INSTALL                 13
#define DSETUP_CB_MSG_BEGIN_INSTALL_RUNTIME         14
#define DSETUP_CB_MSG_BEGIN_INSTALL_DRIVERS         15
#define DSETUP_CB_MSG_BEGIN_RESTORE_DRIVERS         16
#define DSETUP_CB_MSG_FILECOPYERROR                 17


#define DSETUP_CB_UPGRADE_TYPE_MASK             0x000F
#define DSETUP_CB_UPGRADE_KEEP                  0x0001
#define DSETUP_CB_UPGRADE_SAFE                  0x0002
#define DSETUP_CB_UPGRADE_FORCE                 0x0004
#define DSETUP_CB_UPGRADE_UNKNOWN               0x0008

#define DSETUP_CB_UPGRADE_HASWARNINGS           0x0100
#define DSETUP_CB_UPGRADE_CANTBACKUP            0x0200

#define DSETUP_CB_UPGRADE_DEVICE_ACTIVE         0x0800

#define DSETUP_CB_UPGRADE_DEVICE_DISPLAY        0x1000
#define DSETUP_CB_UPGRADE_DEVICE_MEDIA          0x2000


typedef struct _DSETUP_CB_UPGRADEINFO
{
    DWORD UpgradeFlags;
} DSETUP_CB_UPGRADEINFO;

typedef struct _DSETUP_CB_FILECOPYERROR
{
    DWORD dwError;
} DSETUP_CB_FILECOPYERROR;


#ifdef _WIN32
//
// Data Structures
//
#ifndef UNICODE_ONLY
typedef struct _DIRECTXREGISTERAPPA {
    DWORD    dwSize;
    DWORD    dwFlags;
    LPSTR    lpszApplicationName;
    LPGUID   lpGUID;
    LPSTR    lpszFilename;
    LPSTR    lpszCommandLine;
    LPSTR    lpszPath;
    LPSTR    lpszCurrentDirectory;
} DIRECTXREGISTERAPPA, *PDIRECTXREGISTERAPPA, *LPDIRECTXREGISTERAPPA;
#endif //!UNICODE_ONLY
#ifndef ANSI_ONLY
typedef struct _DIRECTXREGISTERAPPW {
    DWORD    dwSize;
    DWORD    dwFlags;
    LPWSTR   lpszApplicationName;
    LPGUID   lpGUID;
    LPWSTR   lpszFilename;
    LPWSTR   lpszCommandLine;
    LPWSTR   lpszPath;
    LPWSTR   lpszCurrentDirectory;
} DIRECTXREGISTERAPPW, *PDIRECTXREGISTERAPPW, *LPDIRECTXREGISTERAPPW;
#endif //!ANSI_ONLY
#ifdef UNICODE
typedef DIRECTXREGISTERAPPW DIRECTXREGISTERAPP;
typedef PDIRECTXREGISTERAPPW PDIRECTXREGISTERAPP;
typedef LPDIRECTXREGISTERAPPW LPDIRECTXREGISTERAPP;
#else
typedef DIRECTXREGISTERAPPA DIRECTXREGISTERAPP;
typedef PDIRECTXREGISTERAPPA PDIRECTXREGISTERAPP;
typedef LPDIRECTXREGISTERAPPA LPDIRECTXREGISTERAPP;
#endif // UNICODE


//
// API
//
#ifndef UNICODE_ONLY
INT
WINAPI
DirectXSetupA(
    HWND  hWnd,
    LPSTR lpszRootPath,
    DWORD dwFlags
    );
#endif //!UNICODE_ONLY
#ifndef ANSI_ONLY
INT
WINAPI
DirectXSetupW(
    HWND   hWnd,
    LPWSTR lpszRootPath,
    DWORD  dwFlags
    );
#endif //!ANSI_ONLY
#ifdef UNICODE
#define DirectXSetup  DirectXSetupW
#else
#define DirectXSetup  DirectXSetupA
#endif // !UNICODE

#ifndef UNICODE_ONLY
INT
WINAPI
DirectXDeviceDriverSetupA(
    HWND  hWnd,
    LPSTR lpszDriverClass,
    LPSTR lpszDriverPath,
    DWORD dwFlags
    );
#endif //!UNICODE_ONLY
#ifndef ANSI_ONLY
INT
WINAPI
DirectXDeviceDriverSetupW(
    HWND   hWnd,
    LPWSTR lpszDriverClass,
    LPWSTR lpszDriverPath,
    DWORD  dwFlags
    );
#endif //!ANSI_ONLY
#ifdef UNICODE
#define DirectXDeviceDriverSetup  DirectXDeviceDriverSetupW
#else
#define DirectXDeviceDriverSetup  DirectXDeviceDriverSetupA
#endif // !UNICODE

#ifndef UNICODE_ONLY
INT
WINAPI
DirectXRegisterApplicationA(
    HWND                  hWnd,
    LPDIRECTXREGISTERAPPA lpDXRegApp
    );
#endif //!UNICODE_ONLY
#ifndef ANSI_ONLY
INT
WINAPI
DirectXRegisterApplicationW(
    HWND                  hWnd,
    LPDIRECTXREGISTERAPPW lpDXRegApp
    );
#endif //!ANSI_ONLY
#ifdef UNICODE
#define DirectXRegisterApplication  DirectXRegisterApplicationW
#else
#define DirectXRegisterApplication  DirectXRegisterApplicationA
#endif // !UNICODE

INT
WINAPI
DirectXUnRegisterApplication(
    HWND     hWnd,
    LPGUID   lpGUID
    );

//
// Function Pointers
//
#ifdef UNICODE
typedef INT (WINAPI * LPDIRECTXSETUP)(HWND, LPWSTR, DWORD);
typedef INT (WINAPI * LPDIRECTXDEVICEDRIVERSETUP)(HWND, LPWSTR, LPSTR, DWORD);
typedef INT (WINAPI * LPDIRECTXREGISTERAPPLICATION)(HWND, LPDIRECTXREGISTERAPPW);
#else
typedef INT (WINAPI * LPDIRECTXSETUP)(HWND, LPSTR, DWORD);
typedef INT (WINAPI * LPDIRECTXDEVICEDRIVERSETUP)(HWND, LPSTR, LPSTR, DWORD);
typedef INT (WINAPI * LPDIRECTXREGISTERAPPLICATION)(HWND, LPDIRECTXREGISTERAPPA);
#endif // UNICODE

typedef DWORD (FAR PASCAL * DSETUP_CALLBACK)(DWORD Reason,
                                  DWORD MsgType,       /* Same as flags to MessageBox */
                                  LPSTR szMessage,
                                  LPSTR szName,
                                  void *pInfo);

INT WINAPI DirectXSetupSetCallback(DSETUP_CALLBACK Callback);
INT WINAPI DirectXSetupGetVersion(DWORD *lpdwVersion, DWORD *lpdwMinorVersion);

#endif // WIN32


#ifdef __cplusplus
};
#endif

#endif
