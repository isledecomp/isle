/*==========================================================================;
 *
 *  Copyright (C) 1994-1997 Microsoft Corporation.  All Rights Reserved.
 *
 *  File:       dplay.h
 *  Content:    DirectPlay include file
 *
 ***************************************************************************/

#ifndef __DPLAY_INCLUDED__
#define __DPLAY_INCLUDED__

#include <ole2.h>       // for DECLARE_INTERFACE and HRESULT

#define _FACDP  0x877
#define MAKE_DPHRESULT( code )    MAKE_HRESULT( 1, _FACDP, code )

#ifdef __cplusplus
extern "C" {
#endif

/*
 * GUIDS used by DirectPlay objects
 */
DEFINE_GUID(IID_IDirectPlay2, 0x2b74f7c0, 0x9154, 0x11cf, 0xa9, 0xcd, 0x0, 0xaa, 0x0, 0x68, 0x86, 0xe3);
DEFINE_GUID(IID_IDirectPlay2A,0x9d460580, 0xa822, 0x11cf, 0x96, 0xc, 0x0, 0x80, 0xc7, 0x53, 0x4e, 0x82);

DEFINE_GUID(IID_IDirectPlay3, 0x133efe40, 0x32dc, 0x11d0, 0x9c, 0xfb, 0x0, 0xa0, 0xc9, 0xa, 0x43, 0xcb);
DEFINE_GUID(IID_IDirectPlay3A,0x133efe41, 0x32dc, 0x11d0, 0x9c, 0xfb, 0x0, 0xa0, 0xc9, 0xa, 0x43, 0xcb);

// {D1EB6D20-8923-11d0-9D97-00A0C90A43CB}
DEFINE_GUID(CLSID_DirectPlay,0xd1eb6d20, 0x8923, 0x11d0, 0x9d, 0x97, 0x0, 0xa0, 0xc9, 0xa, 0x43, 0xcb);

/*
 * GUIDS used by Service Providers shipped with DirectPlay
 * Use these to identify Service Provider returned by EnumConnections
 */

// GUID for IPX service provider
// {685BC400-9D2C-11cf-A9CD-00AA006886E3}
DEFINE_GUID(DPSPGUID_IPX, 
0x685bc400, 0x9d2c, 0x11cf, 0xa9, 0xcd, 0x0, 0xaa, 0x0, 0x68, 0x86, 0xe3);

// GUID for TCP/IP service provider
// 36E95EE0-8577-11cf-960C-0080C7534E82
DEFINE_GUID(DPSPGUID_TCPIP,
0x36E95EE0, 0x8577, 0x11cf, 0x96, 0xc, 0x0, 0x80, 0xc7, 0x53, 0x4e, 0x82);

// GUID for Serial service provider
// {0F1D6860-88D9-11cf-9C4E-00A0C905425E}
DEFINE_GUID(DPSPGUID_SERIAL,						
0xf1d6860, 0x88d9, 0x11cf, 0x9c, 0x4e, 0x0, 0xa0, 0xc9, 0x5, 0x42, 0x5e);

// GUID for Modem service provider
// {44EAA760-CB68-11cf-9C4E-00A0C905425E}
DEFINE_GUID(DPSPGUID_MODEM,
0x44eaa760, 0xcb68, 0x11cf, 0x9c, 0x4e, 0x0, 0xa0, 0xc9, 0x5, 0x42, 0x5e);

/****************************************************************************
 *
 * DirectPlay Structures
 *
 * Various structures used to invoke DirectPlay.
 *
 ****************************************************************************/

#ifndef IDIRECTPLAY2_OR_GREATER
typedef struct IDirectPlay        FAR *LPDIRECTPLAY;
#else
typedef struct IUnknown           FAR *LPDIRECTPLAY;
#endif

typedef struct IDirectPlay2       FAR *LPDIRECTPLAY2;
typedef struct IDirectPlay2       FAR *LPDIRECTPLAY2A;
typedef struct IDirectPlay2       IDirectPlay2A;

typedef struct IDirectPlay3       FAR *LPDIRECTPLAY3;
typedef struct IDirectPlay3       FAR *LPDIRECTPLAY3A;
typedef struct IDirectPlay3       IDirectPlay3A;

/*
 * DPID
 * DirectPlay player and group ID
 */
typedef DWORD DPID, FAR *LPDPID;

/*
 * DPID that system messages come from
 */
#define DPID_SYSMSG         0

/*
 * DPID representing all players in the session
 */
#define DPID_ALLPLAYERS     0

/*
 * DPID representing the server player
 */
#define DPID_SERVERPLAYER	1

/*
 * The player ID is unknown (used with e.g. DPSESSION_NOMESSAGEID)
 */
#define DPID_UNKNOWN		0xFFFFFFFF

/*
 * DPCAPS
 * Used to obtain the capabilities of a DirectPlay object
 */
typedef struct
{
    DWORD dwSize;               // Size of structure, in bytes
    DWORD dwFlags;              // DPCAPS_xxx flags
    DWORD dwMaxBufferSize;      // Maximum message size, in bytes,  for this service provider
    DWORD dwMaxQueueSize;       // Obsolete. 
    DWORD dwMaxPlayers;         // Maximum players/groups (local + remote)
    DWORD dwHundredBaud;        // Bandwidth in 100 bits per second units; 
                                // i.e. 24 is 2400, 96 is 9600, etc.
    DWORD dwLatency;            // Estimated latency; 0 = unknown
    DWORD dwMaxLocalPlayers;    // Maximum # of locally created players allowed
    DWORD dwHeaderLength;       // Maximum header length, in bytes, on messages
                                // added by the service provider
    DWORD dwTimeout;            // Service provider's suggested timeout value
                                // This is how long DirectPlay will wait for 
                                // responses to system messages
} DPCAPS, FAR *LPDPCAPS;

/*
 * This DirectPlay object is the session host.  If the host exits the
 * session, another application will become the host and receive a
 * DPSYS_HOST system message.
 */
#define DPCAPS_ISHOST               0x00000002

/*
 * The service provider bound to this DirectPlay object can optimize
 * group messaging.
 */
#define DPCAPS_GROUPOPTIMIZED       0x00000008

/*
 * The service provider bound to this DirectPlay object can optimize
 * keep alives (see DPSESSION_KEEPALIVE)
 */
#define DPCAPS_KEEPALIVEOPTIMIZED   0x00000010

/*
 * The service provider bound to this DirectPlay object can optimize
 * guaranteed message delivery.
 */
#define DPCAPS_GUARANTEEDOPTIMIZED  0x00000020

/*
 * This DirectPlay object supports guaranteed message delivery.
 */
#define DPCAPS_GUARANTEEDSUPPORTED  0x00000040

/*
 * This DirectPlay object supports digital signing of messages.
 */
#define DPCAPS_SIGNINGSUPPORTED     0x00000080

/*
 * This DirectPlay object supports encryption of messages.
 */
#define DPCAPS_ENCRYPTIONSUPPORTED  0x00000100


/*
 * DPSESSIONDESC2
 * Used to describe the properties of a DirectPlay
 * session instance
 */
typedef struct
{
    DWORD   dwSize;             // Size of structure
    DWORD   dwFlags;            // DPSESSION_xxx flags
    GUID    guidInstance;       // ID for the session instance
    GUID    guidApplication;    // GUID of the DirectPlay application.
                                // GUID_NULL for all applications.
    DWORD   dwMaxPlayers;       // Maximum # players allowed in session
    DWORD   dwCurrentPlayers;   // Current # players in session (read only)
    union
    {                           // Name of the session
        LPWSTR  lpszSessionName;    // Unicode
        LPSTR   lpszSessionNameA;   // ANSI
    };
    union
    {                           // Password of the session (optional)
        LPWSTR  lpszPassword;       // Unicode
        LPSTR   lpszPasswordA;      // ANSI
    };
    DWORD   dwReserved1;        // Reserved for future MS use.
    DWORD   dwReserved2;
    DWORD   dwUser1;            // For use by the application
    DWORD   dwUser2;
    DWORD   dwUser3;
    DWORD   dwUser4;
} DPSESSIONDESC2, FAR *LPDPSESSIONDESC2;

/*
 * LPCDPSESSIONDESC2
 * A constant pointer to DPSESSIONDESC2
 */
typedef const DPSESSIONDESC2 FAR *LPCDPSESSIONDESC2;
 
/*
 * Applications cannot create new players in this session.
 */
#define DPSESSION_NEWPLAYERSDISABLED    0x00000001 

/*
 * If the DirectPlay object that created the session, the host,
 * quits, then the host will attempt to migrate to another
 * DirectPlay object so that new players can continue to be created
 * and new applications can join the session.
 */
#define DPSESSION_MIGRATEHOST           0x00000004

/*
 * This flag tells DirectPlay not to set the idPlayerTo and idPlayerFrom 
 * fields in player messages.  This cuts two DWORD's off the message 
 * overhead.
 */
#define DPSESSION_NOMESSAGEID           0x00000008


/*
 * This flag tells DirectPlay to not allow any new applications to
 * join the session.  Applications already in the session can still
 * create new players.
 */
#define DPSESSION_JOINDISABLED          0x00000020

/*
 * This flag tells DirectPlay to detect when remote players 
 * exit abnormally (e.g. their computer or modem gets unplugged)
 */
#define DPSESSION_KEEPALIVE             0x00000040

/*
 * This flag tells DirectPlay not to send a message to all players
 * when a players remote data changes
 */
#define DPSESSION_NODATAMESSAGES        0x00000080

/*
 * This flag indicates that the session belongs to a secure server
 * and needs user authentication
 */
#define DPSESSION_SECURESERVER          0x00000100

/*
 * This flag indicates that the session is private and requirs a password
 * for EnumSessions as well as Open.
 */
#define DPSESSION_PRIVATE               0x00000200

/*
 * This flag indicates that the session requires a password for joining.
 */
#define DPSESSION_PASSWORDREQUIRED      0x00000400

/*
 * This flag tells DirectPlay to route all messages through the server
 */
#define DPSESSION_MULTICASTSERVER		0x00000800

/*
 * This flag tells DirectPlay to only download information about the
 * DPPLAYER_SERVERPLAYER.  
 */
#define DPSESSION_CLIENTSERVER			0x00001000

/*
 * DPNAME
 * Used to hold the name of a DirectPlay entity
 * like a player or a group
 */
typedef struct 
{
    DWORD   dwSize;             // Size of structure
    DWORD   dwFlags;            // Not used. Must be zero.
    union
    {                           // The short or friendly name
        LPWSTR  lpszShortName;  // Unicode
        LPSTR   lpszShortNameA; // ANSI
    };
    union
    {                           // The long or formal name
        LPWSTR  lpszLongName;   // Unicode
        LPSTR   lpszLongNameA;  // ANSI
    };

} DPNAME, FAR *LPDPNAME;

/*
 * LPCDPNAME
 * A constant pointer to DPNAME
 */
typedef const DPNAME FAR *LPCDPNAME;

/*
 * DPCREDENTIALS
 * Used to hold the user name and password of a DirectPlay user
 */
typedef struct 
{
    DWORD dwSize;               // Size of structure
    DWORD dwFlags;              // Not used. Must be zero.
    union
    {                           // User name of the account
        LPWSTR  lpszUsername;   // Unicode
        LPSTR   lpszUsernameA;  // ANSI
    };    
    union
    {                           // Password of the account
        LPWSTR  lpszPassword;   // Unicode
        LPSTR   lpszPasswordA;  // ANSI
    };    
    union
    {                           // Domain name of the account
        LPWSTR  lpszDomain;     // Unicode
        LPSTR   lpszDomainA;    // ANSI
    };    
} DPCREDENTIALS, FAR *LPDPCREDENTIALS;

typedef const DPCREDENTIALS FAR *LPCDPCREDENTIALS;

/*
 * DPSECURITYDESC
 * Used to describe the security properties of a DirectPlay
 * session instance
 */
typedef struct 
{
    DWORD dwSize;                   // Size of structure
    DWORD dwFlags;                  // Not used. Must be zero.
    union
    {                               // SSPI provider name
        LPWSTR  lpszSSPIProvider;   // Unicode
        LPSTR   lpszSSPIProviderA;  // ANSI
    };
    union
    {                               // CAPI provider name
        LPWSTR lpszCAPIProvider;    // Unicode
        LPSTR  lpszCAPIProviderA;   // ANSI
    };
    DWORD dwCAPIProviderType;       // Crypto Service Provider type
    DWORD dwEncryptionAlgorithm;    // Encryption Algorithm type
} DPSECURITYDESC, FAR *LPDPSECURITYDESC;

typedef const DPSECURITYDESC FAR *LPCDPSECURITYDESC;

/*
 * DPACCOUNTDESC
 * Used to describe a user membership account
 */
typedef struct 
{
    DWORD dwSize;                   // Size of structure
    DWORD dwFlags;                  // Not used. Must be zero.
    union
    {                               // Account identifier
        LPWSTR  lpszAccountID;      // Unicode
        LPSTR   lpszAccountIDA;     // ANSI
    };
} DPACCOUNTDESC, FAR *LPDPACCOUNTDESC;

typedef const DPACCOUNTDESC FAR *LPCDPACCOUNTDESC;

/*
 * LPCGUID
 * A constant pointer to a guid
 */
typedef const GUID FAR *LPCGUID;

/*
 * DPLCONNECTION
 * Used to hold all in the informaion needed to connect
 * an application to a session or create a session
 */
typedef struct
{
    DWORD               dwSize;             // Size of this structure
    DWORD               dwFlags;            // Flags specific to this structure
    LPDPSESSIONDESC2    lpSessionDesc;      // Pointer to session desc to use on connect
    LPDPNAME            lpPlayerName;       // Pointer to Player name structure
    GUID                guidSP;             // GUID of the DPlay SP to use
    LPVOID              lpAddress;          // Address for service provider
    DWORD               dwAddressSize;      // Size of address data
} DPLCONNECTION, FAR *LPDPLCONNECTION;

/*
 * LPCDPLCONNECTION
 * A constant pointer to DPLCONNECTION
 */
typedef const DPLCONNECTION FAR *LPCDPLCONNECTION;

/*
 * DPCHAT
 * Used to hold the a DirectPlay chat message
 */
typedef struct
{
    DWORD               dwSize;
    DWORD               dwFlags;
    union
    {                          // Message string
        LPWSTR  lpszMessage;   // Unicode
        LPSTR   lpszMessageA;  // ANSI
    };    
} DPCHAT, FAR * LPDPCHAT;

/****************************************************************************
 *
 * Prototypes for DirectPlay callback functions
 *
 ****************************************************************************/

/*
 * Callback for IDirectPlay2::EnumSessions
 */
typedef BOOL (FAR PASCAL * LPDPENUMSESSIONSCALLBACK2)(
    LPCDPSESSIONDESC2   lpThisSD,
    LPDWORD             lpdwTimeOut,
    DWORD               dwFlags,
    LPVOID              lpContext );

/*
 * This flag is set on the EnumSessions callback dwFlags parameter when
 * the time out has occurred. There will be no session data for this 
 * callback. If *lpdwTimeOut is set to a non-zero value and the 
 * EnumSessionsCallback function returns TRUE then EnumSessions will 
 * continue waiting until the next timeout occurs. Timeouts are in 
 * milliseconds.
 */
#define DPESC_TIMEDOUT          0x00000001


/*
 * Callback for IDirectPlay2::EnumPlayers
 *              IDirectPlay2::EnumGroups
 *              IDirectPlay2::EnumGroupPlayers
 */
typedef BOOL (FAR PASCAL *LPDPENUMPLAYERSCALLBACK2)(
    DPID            dpId,
    DWORD           dwPlayerType,
    LPCDPNAME       lpName,
    DWORD           dwFlags,
    LPVOID          lpContext );


/*
 * Unicode callback for DirectPlayEnumerate
 * This callback prototype will be used if compiling
 * for Unicode strings
 */
typedef BOOL (FAR PASCAL * LPDPENUMDPCALLBACK)(
    LPGUID      lpguidSP,
    LPWSTR      lpSPName,
    DWORD       dwMajorVersion,
    DWORD       dwMinorVersion,
    LPVOID      lpContext);

/*
 * ANSI callback for DirectPlayEnumerate
 * This callback prototype will be used if compiling
 * for ANSI strings
 */
typedef BOOL (FAR PASCAL * LPDPENUMDPCALLBACKA)(
    LPGUID      lpguidSP,
    LPSTR       lpSPName,
    DWORD       dwMajorVersion,     
    DWORD       dwMinorVersion,
    LPVOID      lpContext);

/*
 * Callback for IDirectPlay3(A)::EnumConnections
 */
typedef BOOL (FAR PASCAL * LPDPENUMCONNECTIONSCALLBACK)(
    LPCGUID     lpguidSP,
	LPVOID		lpConnection,
	DWORD		dwConnectionSize,
    LPCDPNAME   lpName,
	DWORD 		dwFlags,
	LPVOID 		lpContext);


/*
 * API's
 */

#ifdef UNICODE
#define DirectPlayEnumerate     DirectPlayEnumerateW
#else
#define DirectPlayEnumerate     DirectPlayEnumerateA
#endif // UNICODE

extern HRESULT WINAPI DirectPlayEnumerateA( LPDPENUMDPCALLBACKA, LPVOID );
extern HRESULT WINAPI DirectPlayEnumerateW( LPDPENUMDPCALLBACK, LPVOID );
extern HRESULT WINAPI DirectPlayCreate( LPGUID lpGUID, LPDIRECTPLAY *lplpDP, IUnknown *pUnk);

/****************************************************************************
 *
 * IDirectPlay2 (and IDirectPlay2A) Interface
 *
 ****************************************************************************/

#undef INTERFACE
#define INTERFACE IDirectPlay2
DECLARE_INTERFACE_( IDirectPlay2, IUnknown )
{
    /*** IUnknown methods ***/
    STDMETHOD(QueryInterface)       (THIS_ REFIID riid, LPVOID * ppvObj) PURE;
    STDMETHOD_(ULONG,AddRef)        (THIS)  PURE;
    STDMETHOD_(ULONG,Release)       (THIS) PURE;
    /*** IDirectPlay2 methods ***/
    STDMETHOD(AddPlayerToGroup)     (THIS_ DPID, DPID) PURE;
    STDMETHOD(Close)                (THIS) PURE;
    STDMETHOD(CreateGroup)          (THIS_ LPDPID,LPDPNAME,LPVOID,DWORD,DWORD) PURE;
    STDMETHOD(CreatePlayer)         (THIS_ LPDPID,LPDPNAME,HANDLE,LPVOID,DWORD,DWORD) PURE;
    STDMETHOD(DeletePlayerFromGroup)(THIS_ DPID,DPID) PURE;
    STDMETHOD(DestroyGroup)         (THIS_ DPID) PURE;
    STDMETHOD(DestroyPlayer)        (THIS_ DPID) PURE;
    STDMETHOD(EnumGroupPlayers)     (THIS_ DPID,LPGUID,LPDPENUMPLAYERSCALLBACK2,LPVOID,DWORD) PURE;
    STDMETHOD(EnumGroups)           (THIS_ LPGUID,LPDPENUMPLAYERSCALLBACK2,LPVOID,DWORD) PURE;
    STDMETHOD(EnumPlayers)          (THIS_ LPGUID,LPDPENUMPLAYERSCALLBACK2,LPVOID,DWORD) PURE;
    STDMETHOD(EnumSessions)         (THIS_ LPDPSESSIONDESC2,DWORD,LPDPENUMSESSIONSCALLBACK2,LPVOID,DWORD) PURE;
    STDMETHOD(GetCaps)              (THIS_ LPDPCAPS,DWORD) PURE;
    STDMETHOD(GetGroupData)         (THIS_ DPID,LPVOID,LPDWORD,DWORD) PURE;
    STDMETHOD(GetGroupName)         (THIS_ DPID,LPVOID,LPDWORD) PURE;
    STDMETHOD(GetMessageCount)      (THIS_ DPID, LPDWORD) PURE;
    STDMETHOD(GetPlayerAddress)     (THIS_ DPID,LPVOID,LPDWORD) PURE;
    STDMETHOD(GetPlayerCaps)        (THIS_ DPID,LPDPCAPS,DWORD) PURE;
    STDMETHOD(GetPlayerData)        (THIS_ DPID,LPVOID,LPDWORD,DWORD) PURE;
    STDMETHOD(GetPlayerName)        (THIS_ DPID,LPVOID,LPDWORD) PURE;
    STDMETHOD(GetSessionDesc)       (THIS_ LPVOID,LPDWORD) PURE;
    STDMETHOD(Initialize)           (THIS_ LPGUID) PURE;
    STDMETHOD(Open)                 (THIS_ LPDPSESSIONDESC2,DWORD) PURE;
    STDMETHOD(Receive)              (THIS_ LPDPID,LPDPID,DWORD,LPVOID,LPDWORD) PURE;
    STDMETHOD(Send)                 (THIS_ DPID, DPID, DWORD, LPVOID, DWORD) PURE;
    STDMETHOD(SetGroupData)         (THIS_ DPID,LPVOID,DWORD,DWORD) PURE;
    STDMETHOD(SetGroupName)         (THIS_ DPID,LPDPNAME,DWORD) PURE;
    STDMETHOD(SetPlayerData)        (THIS_ DPID,LPVOID,DWORD,DWORD) PURE;
    STDMETHOD(SetPlayerName)        (THIS_ DPID,LPDPNAME,DWORD) PURE;
    STDMETHOD(SetSessionDesc)       (THIS_ LPDPSESSIONDESC2,DWORD) PURE;
};

/****************************************************************************
 *
 * IDirectPlay2 interface macros
 *
 ****************************************************************************/

#if !defined(__cplusplus) || defined(CINTERFACE)

#define IDirectPlay2_QueryInterface(p,a,b)          (p)->lpVtbl->QueryInterface(p,a,b)
#define IDirectPlay2_AddRef(p)                      (p)->lpVtbl->AddRef(p)
#define IDirectPlay2_Release(p)                     (p)->lpVtbl->Release(p)
#define IDirectPlay2_AddPlayerToGroup(p,a,b)        (p)->lpVtbl->AddPlayerToGroup(p,a,b)
#define IDirectPlay2_Close(p)                       (p)->lpVtbl->Close(p)
#define IDirectPlay2_CreateGroup(p,a,b,c,d,e)       (p)->lpVtbl->CreateGroup(p,a,b,c,d,e)
#define IDirectPlay2_CreatePlayer(p,a,b,c,d,e,f)    (p)->lpVtbl->CreatePlayer(p,a,b,c,d,e,f)
#define IDirectPlay2_DeletePlayerFromGroup(p,a,b)   (p)->lpVtbl->DeletePlayerFromGroup(p,a,b)
#define IDirectPlay2_DestroyGroup(p,a)              (p)->lpVtbl->DestroyGroup(p,a)
#define IDirectPlay2_DestroyPlayer(p,a)             (p)->lpVtbl->DestroyPlayer(p,a)
#define IDirectPlay2_EnumGroupPlayers(p,a,b,c,d,e)  (p)->lpVtbl->EnumGroupPlayers(p,a,b,c,d,e)
#define IDirectPlay2_EnumGroups(p,a,b,c,d)          (p)->lpVtbl->EnumGroups(p,a,b,c,d)
#define IDirectPlay2_EnumPlayers(p,a,b,c,d)         (p)->lpVtbl->EnumPlayers(p,a,b,c,d)
#define IDirectPlay2_EnumSessions(p,a,b,c,d,e)      (p)->lpVtbl->EnumSessions(p,a,b,c,d,e)
#define IDirectPlay2_GetCaps(p,a,b)                 (p)->lpVtbl->GetCaps(p,a,b)
#define IDirectPlay2_GetMessageCount(p,a,b)         (p)->lpVtbl->GetMessageCount(p,a,b)
#define IDirectPlay2_GetGroupData(p,a,b,c,d)        (p)->lpVtbl->GetGroupData(p,a,b,c,d)
#define IDirectPlay2_GetGroupName(p,a,b,c)          (p)->lpVtbl->GetGroupName(p,a,b,c)
#define IDirectPlay2_GetPlayerAddress(p,a,b,c)      (p)->lpVtbl->GetPlayerAddress(p,a,b,c)
#define IDirectPlay2_GetPlayerCaps(p,a,b,c)         (p)->lpVtbl->GetPlayerCaps(p,a,b,c)
#define IDirectPlay2_GetPlayerData(p,a,b,c,d)       (p)->lpVtbl->GetPlayerData(p,a,b,c,d)
#define IDirectPlay2_GetPlayerName(p,a,b,c)         (p)->lpVtbl->GetPlayerName(p,a,b,c)
#define IDirectPlay2_GetSessionDesc(p,a,b)          (p)->lpVtbl->GetSessionDesc(p,a,b)
#define IDirectPlay2_Initialize(p,a)                (p)->lpVtbl->Initialize(p,a)
#define IDirectPlay2_Open(p,a,b)                    (p)->lpVtbl->Open(p,a,b)
#define IDirectPlay2_Receive(p,a,b,c,d,e)           (p)->lpVtbl->Receive(p,a,b,c,d,e)
#define IDirectPlay2_Send(p,a,b,c,d,e)              (p)->lpVtbl->Send(p,a,b,c,d,e)
#define IDirectPlay2_SetGroupData(p,a,b,c,d)        (p)->lpVtbl->SetGroupData(p,a,b,c,d)
#define IDirectPlay2_SetGroupName(p,a,b,c)          (p)->lpVtbl->SetGroupName(p,a,b,c)
#define IDirectPlay2_SetPlayerData(p,a,b,c,d)       (p)->lpVtbl->SetPlayerData(p,a,b,c,d)
#define IDirectPlay2_SetPlayerName(p,a,b,c)         (p)->lpVtbl->SetPlayerName(p,a,b,c)
#define IDirectPlay2_SetSessionDesc(p,a,b)          (p)->lpVtbl->SetSessionDesc(p,a,b)

#else /* C++ */

#define IDirectPlay2_QueryInterface(p,a,b)          (p)->QueryInterface(a,b)
#define IDirectPlay2_AddRef(p)                      (p)->AddRef()
#define IDirectPlay2_Release(p)                     (p)->Release()
#define IDirectPlay2_AddPlayerToGroup(p,a,b)        (p)->AddPlayerToGroup(a,b)
#define IDirectPlay2_Close(p)                       (p)->Close()
#define IDirectPlay2_CreateGroup(p,a,b,c,d,e)       (p)->CreateGroup(a,b,c,d,e)
#define IDirectPlay2_CreatePlayer(p,a,b,c,d,e,f)    (p)->CreatePlayer(a,b,c,d,e,f)
#define IDirectPlay2_DeletePlayerFromGroup(p,a,b)   (p)->DeletePlayerFromGroup(a,b)
#define IDirectPlay2_DestroyGroup(p,a)              (p)->DestroyGroup(a)
#define IDirectPlay2_DestroyPlayer(p,a)             (p)->DestroyPlayer(a)
#define IDirectPlay2_EnumGroupPlayers(p,a,b,c,d,e)  (p)->EnumGroupPlayers(a,b,c,d,e)
#define IDirectPlay2_EnumGroups(p,a,b,c,d)          (p)->EnumGroups(a,b,c,d)
#define IDirectPlay2_EnumPlayers(p,a,b,c,d)         (p)->EnumPlayers(a,b,c,d)
#define IDirectPlay2_EnumSessions(p,a,b,c,d,e)      (p)->EnumSessions(a,b,c,d,e)
#define IDirectPlay2_GetCaps(p,a,b)                 (p)->GetCaps(a,b)
#define IDirectPlay2_GetMessageCount(p,a,b)         (p)->GetMessageCount(a,b)
#define IDirectPlay2_GetGroupData(p,a,b,c,d)        (p)->GetGroupData(a,b,c,d)
#define IDirectPlay2_GetGroupName(p,a,b,c)          (p)->GetGroupName(a,b,c)
#define IDirectPlay2_GetPlayerAddress(p,a,b,c)      (p)->GetPlayerAddress(a,b,c)
#define IDirectPlay2_GetPlayerCaps(p,a,b,c)         (p)->GetPlayerCaps(a,b,c)
#define IDirectPlay2_GetPlayerData(p,a,b,c,d)       (p)->GetPlayerData(a,b,c,d)
#define IDirectPlay2_GetPlayerName(p,a,b,c)         (p)->GetPlayerName(a,b,c)
#define IDirectPlay2_GetSessionDesc(p,a,b)          (p)->GetSessionDesc(a,b)
#define IDirectPlay2_Initialize(p,a)                (p)->Initialize(a)
#define IDirectPlay2_Open(p,a,b)                    (p)->Open(a,b)
#define IDirectPlay2_Receive(p,a,b,c,d,e)           (p)->Receive(a,b,c,d,e)
#define IDirectPlay2_Send(p,a,b,c,d,e)              (p)->Send(a,b,c,d,e)
#define IDirectPlay2_SetGroupData(p,a,b,c,d)        (p)->SetGroupData(a,b,c,d)
#define IDirectPlay2_SetGroupName(p,a,b,c)          (p)->SetGroupName(a,b,c)
#define IDirectPlay2_SetPlayerData(p,a,b,c,d)       (p)->SetPlayerData(a,b,c,d)
#define IDirectPlay2_SetPlayerName(p,a,b,c)         (p)->SetPlayerName(a,b,c)
#define IDirectPlay2_SetSessionDesc(p,a,b)          (p)->SetSessionDesc(a,b)

#endif

/****************************************************************************
 *
 * IDirectPlay3 (and IDirectPlay3A) Interface
 *
 ****************************************************************************/

#undef INTERFACE
#define INTERFACE IDirectPlay3
DECLARE_INTERFACE_( IDirectPlay3, IDirectPlay2 )
{
    /*** IUnknown methods ***/
    STDMETHOD(QueryInterface)       (THIS_ REFIID riid, LPVOID * ppvObj) PURE;
    STDMETHOD_(ULONG,AddRef)        (THIS)  PURE;
    STDMETHOD_(ULONG,Release)       (THIS) PURE;
    /*** IDirectPlay2 methods ***/
    STDMETHOD(AddPlayerToGroup)     (THIS_ DPID, DPID) PURE;
    STDMETHOD(Close)                (THIS) PURE;
    STDMETHOD(CreateGroup)          (THIS_ LPDPID,LPDPNAME,LPVOID,DWORD,DWORD) PURE;
    STDMETHOD(CreatePlayer)         (THIS_ LPDPID,LPDPNAME,HANDLE,LPVOID,DWORD,DWORD) PURE;
    STDMETHOD(DeletePlayerFromGroup)(THIS_ DPID,DPID) PURE;
    STDMETHOD(DestroyGroup)         (THIS_ DPID) PURE;
    STDMETHOD(DestroyPlayer)        (THIS_ DPID) PURE;
    STDMETHOD(EnumGroupPlayers)     (THIS_ DPID,LPGUID,LPDPENUMPLAYERSCALLBACK2,LPVOID,DWORD) PURE;
    STDMETHOD(EnumGroups)           (THIS_ LPGUID,LPDPENUMPLAYERSCALLBACK2,LPVOID,DWORD) PURE;
    STDMETHOD(EnumPlayers)          (THIS_ LPGUID,LPDPENUMPLAYERSCALLBACK2,LPVOID,DWORD) PURE;
    STDMETHOD(EnumSessions)         (THIS_ LPDPSESSIONDESC2,DWORD,LPDPENUMSESSIONSCALLBACK2,LPVOID,DWORD) PURE;
    STDMETHOD(GetCaps)              (THIS_ LPDPCAPS,DWORD) PURE;
    STDMETHOD(GetGroupData)         (THIS_ DPID,LPVOID,LPDWORD,DWORD) PURE;
    STDMETHOD(GetGroupName)         (THIS_ DPID,LPVOID,LPDWORD) PURE;
    STDMETHOD(GetMessageCount)      (THIS_ DPID, LPDWORD) PURE;
    STDMETHOD(GetPlayerAddress)     (THIS_ DPID,LPVOID,LPDWORD) PURE;
    STDMETHOD(GetPlayerCaps)        (THIS_ DPID,LPDPCAPS,DWORD) PURE;
    STDMETHOD(GetPlayerData)        (THIS_ DPID,LPVOID,LPDWORD,DWORD) PURE;
    STDMETHOD(GetPlayerName)        (THIS_ DPID,LPVOID,LPDWORD) PURE;
    STDMETHOD(GetSessionDesc)       (THIS_ LPVOID,LPDWORD) PURE;
    STDMETHOD(Initialize)           (THIS_ LPGUID) PURE;
    STDMETHOD(Open)                 (THIS_ LPDPSESSIONDESC2,DWORD) PURE;
    STDMETHOD(Receive)              (THIS_ LPDPID,LPDPID,DWORD,LPVOID,LPDWORD) PURE;
    STDMETHOD(Send)                 (THIS_ DPID, DPID, DWORD, LPVOID, DWORD) PURE;
    STDMETHOD(SetGroupData)         (THIS_ DPID,LPVOID,DWORD,DWORD) PURE;
    STDMETHOD(SetGroupName)         (THIS_ DPID,LPDPNAME,DWORD) PURE;
    STDMETHOD(SetPlayerData)        (THIS_ DPID,LPVOID,DWORD,DWORD) PURE;
    STDMETHOD(SetPlayerName)        (THIS_ DPID,LPDPNAME,DWORD) PURE;
    STDMETHOD(SetSessionDesc)       (THIS_ LPDPSESSIONDESC2,DWORD) PURE;
    /*** IDirectPlay3 methods ***/
    STDMETHOD(AddGroupToGroup)      (THIS_ DPID, DPID) PURE;
    STDMETHOD(CreateGroupInGroup)   (THIS_ DPID,LPDPID,LPDPNAME,LPVOID,DWORD,DWORD) PURE;
    STDMETHOD(DeleteGroupFromGroup)	(THIS_ DPID,DPID) PURE;	
    STDMETHOD(EnumConnections)     	(THIS_ LPCGUID,LPDPENUMCONNECTIONSCALLBACK,LPVOID,DWORD) PURE;
    STDMETHOD(EnumGroupsInGroup)	(THIS_ DPID,LPGUID,LPDPENUMPLAYERSCALLBACK2,LPVOID,DWORD) PURE;
	STDMETHOD(GetGroupConnectionSettings)(THIS_ DWORD, DPID, LPVOID, LPDWORD) PURE;
	STDMETHOD(InitializeConnection) (THIS_ LPVOID,DWORD) PURE;
    STDMETHOD(SecureOpen)           (THIS_ LPCDPSESSIONDESC2,DWORD,LPCDPSECURITYDESC,LPCDPCREDENTIALS) PURE;
	STDMETHOD(SendChatMessage)      (THIS_ DPID,DPID,DWORD,LPDPCHAT);
	STDMETHOD(SetGroupConnectionSettings)(THIS_ DWORD,DPID,LPDPLCONNECTION) PURE;
	STDMETHOD(StartSession)         (THIS_ DWORD,DPID);
	STDMETHOD(GetGroupFlags)        (THIS_ DPID,LPDWORD);
	STDMETHOD(GetGroupParent)       (THIS_ DPID,LPDPID);
	STDMETHOD(GetPlayerAccount)     (THIS_ DPID, DWORD, LPVOID, LPDWORD) PURE;
	STDMETHOD(GetPlayerFlags)       (THIS_ DPID,LPDWORD);
};

/****************************************************************************
 *
 * IDirectPlay3 interface macros
 *
 ****************************************************************************/

#if !defined(__cplusplus) || defined(CINTERFACE)

#define IDirectPlay3_QueryInterface(p,a,b)          (p)->lpVtbl->QueryInterface(p,a,b)
#define IDirectPlay3_AddRef(p)                      (p)->lpVtbl->AddRef(p)
#define IDirectPlay3_Release(p)                     (p)->lpVtbl->Release(p)
#define IDirectPlay3_AddPlayerToGroup(p,a,b)        (p)->lpVtbl->AddPlayerToGroup(p,a,b)
#define IDirectPlay3_Close(p)                       (p)->lpVtbl->Close(p)
#define IDirectPlay3_CreateGroup(p,a,b,c,d,e)       (p)->lpVtbl->CreateGroup(p,a,b,c,d,e)
#define IDirectPlay3_CreatePlayer(p,a,b,c,d,e,f)    (p)->lpVtbl->CreatePlayer(p,a,b,c,d,e,f)
#define IDirectPlay3_DeletePlayerFromGroup(p,a,b)   (p)->lpVtbl->DeletePlayerFromGroup(p,a,b)
#define IDirectPlay3_DestroyGroup(p,a)              (p)->lpVtbl->DestroyGroup(p,a)
#define IDirectPlay3_DestroyPlayer(p,a)             (p)->lpVtbl->DestroyPlayer(p,a)
#define IDirectPlay3_EnumGroupPlayers(p,a,b,c,d,e)  (p)->lpVtbl->EnumGroupPlayers(p,a,b,c,d,e)
#define IDirectPlay3_EnumGroups(p,a,b,c,d)          (p)->lpVtbl->EnumGroups(p,a,b,c,d)
#define IDirectPlay3_EnumPlayers(p,a,b,c,d)         (p)->lpVtbl->EnumPlayers(p,a,b,c,d)
#define IDirectPlay3_EnumSessions(p,a,b,c,d,e)      (p)->lpVtbl->EnumSessions(p,a,b,c,d,e)
#define IDirectPlay3_GetCaps(p,a,b)                 (p)->lpVtbl->GetCaps(p,a,b)
#define IDirectPlay3_GetMessageCount(p,a,b)         (p)->lpVtbl->GetMessageCount(p,a,b)
#define IDirectPlay3_GetGroupData(p,a,b,c,d)        (p)->lpVtbl->GetGroupData(p,a,b,c,d)
#define IDirectPlay3_GetGroupName(p,a,b,c)          (p)->lpVtbl->GetGroupName(p,a,b,c)
#define IDirectPlay3_GetPlayerAddress(p,a,b,c)      (p)->lpVtbl->GetPlayerAddress(p,a,b,c)
#define IDirectPlay3_GetPlayerCaps(p,a,b,c)         (p)->lpVtbl->GetPlayerCaps(p,a,b,c)
#define IDirectPlay3_GetPlayerData(p,a,b,c,d)       (p)->lpVtbl->GetPlayerData(p,a,b,c,d)
#define IDirectPlay3_GetPlayerName(p,a,b,c)         (p)->lpVtbl->GetPlayerName(p,a,b,c)
#define IDirectPlay3_GetSessionDesc(p,a,b)          (p)->lpVtbl->GetSessionDesc(p,a,b)
#define IDirectPlay3_Initialize(p,a)                (p)->lpVtbl->Initialize(p,a)
#define IDirectPlay3_Open(p,a,b)                    (p)->lpVtbl->Open(p,a,b)
#define IDirectPlay3_Receive(p,a,b,c,d,e)           (p)->lpVtbl->Receive(p,a,b,c,d,e)
#define IDirectPlay3_Send(p,a,b,c,d,e)              (p)->lpVtbl->Send(p,a,b,c,d,e)
#define IDirectPlay3_SetGroupData(p,a,b,c,d)        (p)->lpVtbl->SetGroupData(p,a,b,c,d)
#define IDirectPlay3_SetGroupName(p,a,b,c)          (p)->lpVtbl->SetGroupName(p,a,b,c)
#define IDirectPlay3_SetPlayerData(p,a,b,c,d)       (p)->lpVtbl->SetPlayerData(p,a,b,c,d)
#define IDirectPlay3_SetPlayerName(p,a,b,c)         (p)->lpVtbl->SetPlayerName(p,a,b,c)
#define IDirectPlay3_SetSessionDesc(p,a,b)          (p)->lpVtbl->SetSessionDesc(p,a,b)
#define IDirectPlay3_AddGroupToGroup(p,a,b) 		(p)->lpVtbl->AddGroupToGroup(p,a,b)
#define IDirectPlay3_CreateGroupInGroup(p,a,b,c,d,e,f) (p)->lpVtbl->CreateGroupInGroup(p,a,b,c,d,e,f)
#define IDirectPlay3_DeleteGroupFromGroup(p,a,b)   	(p)->lpVtbl->DeleteGroupFromGroup(p,a,b)
#define IDirectPlay3_EnumConnections(p,a,b,c,d) 	(p)->lpVtbl->EnumConnections(p,a,b,c,d)
#define IDirectPlay3_EnumGroupsInGroup(p,a,b,c,d,e) (p)->lpVtbl->EnumGroupsInGroup(p,a,b,c,d,e)
#define IDirectPlay3_GetGroupConnectionSettings(p,a,b,c,d) (p)->lpVtbl->GetGroupConnectionSettings(p,a,b,c,d)
#define IDirectPlay3_InitializeConnection(p,a,b) 	(p)->lpVtbl->InitializeConnection(p,a,b)
#define IDirectPlay3_SecureOpen(p,a,b,c,d)          (p)->lpVtbl->SecureOpen(p,a,b,c,d)
#define IDirectPlay3_SendChatMessage(p,a,b,c,d)     (p)->lpVtbl->SendChatMessage(p,a,b,c,d)
#define IDirectPlay3_SetGroupConnectionSettings(p,a,b,c) (p)->lpVtbl->SetGroupConnectionSettings(p,a,b,c)
#define IDirectPlay3_StartSession(p,a,b)            (p)->lpVtbl->StartSession(p,a,b)
#define IDirectPlay3_GetGroupFlags(p,a,b)           (p)->lpVtbl->GetGroupFlags(p,a,b)
#define IDirectPlay3_GetGroupParent(p,a,b)          (p)->lpVtbl->GetGroupParent(p,a,b)
#define IDirectPlay3_GetPlayerAccount(p,a,b,c,d)    (p)->lpVtbl->GetPlayerAccount(p,a,b,c,d)
#define IDirectPlay3_GetPlayerFlags(p,a,b)          (p)->lpVtbl->GetPlayerFlags(p,a,b)

#else /* C++ */

#define IDirectPlay3_QueryInterface(p,a,b)          (p)->QueryInterface(a,b)
#define IDirectPlay3_AddRef(p)                      (p)->AddRef()
#define IDirectPlay3_Release(p)                     (p)->Release()
#define IDirectPlay3_AddPlayerToGroup(p,a,b)        (p)->AddPlayerToGroup(a,b)
#define IDirectPlay3_Close(p)                       (p)->Close()
#define IDirectPlay3_CreateGroup(p,a,b,c,d,e)       (p)->CreateGroup(a,b,c,d,e)
#define IDirectPlay3_CreatePlayer(p,a,b,c,d,e,f)    (p)->CreatePlayer(a,b,c,d,e,f)
#define IDirectPlay3_DeletePlayerFromGroup(p,a,b)   (p)->DeletePlayerFromGroup(a,b)
#define IDirectPlay3_DestroyGroup(p,a)              (p)->DestroyGroup(a)
#define IDirectPlay3_DestroyPlayer(p,a)             (p)->DestroyPlayer(a)
#define IDirectPlay3_EnumGroupPlayers(p,a,b,c,d,e)  (p)->EnumGroupPlayers(a,b,c,d,e)
#define IDirectPlay3_EnumGroups(p,a,b,c,d)          (p)->EnumGroups(a,b,c,d)
#define IDirectPlay3_EnumPlayers(p,a,b,c,d)         (p)->EnumPlayers(a,b,c,d)
#define IDirectPlay3_EnumSessions(p,a,b,c,d,e)      (p)->EnumSessions(a,b,c,d,e)
#define IDirectPlay3_GetCaps(p,a,b)                 (p)->GetCaps(a,b)
#define IDirectPlay3_GetMessageCount(p,a,b)         (p)->GetMessageCount(a,b)
#define IDirectPlay3_GetGroupData(p,a,b,c,d)        (p)->GetGroupData(a,b,c,d)
#define IDirectPlay3_GetGroupName(p,a,b,c)          (p)->GetGroupName(a,b,c)
#define IDirectPlay3_GetPlayerAddress(p,a,b,c)      (p)->GetPlayerAddress(a,b,c)
#define IDirectPlay3_GetPlayerCaps(p,a,b,c)         (p)->GetPlayerCaps(a,b,c)
#define IDirectPlay3_GetPlayerData(p,a,b,c,d)       (p)->GetPlayerData(a,b,c,d)
#define IDirectPlay3_GetPlayerName(p,a,b,c)         (p)->GetPlayerName(a,b,c)
#define IDirectPlay3_GetSessionDesc(p,a,b)          (p)->GetSessionDesc(a,b)
#define IDirectPlay3_Initialize(p,a)                (p)->Initialize(a)
#define IDirectPlay3_Open(p,a,b)                    (p)->Open(a,b)
#define IDirectPlay3_Receive(p,a,b,c,d,e)           (p)->Receive(a,b,c,d,e)
#define IDirectPlay3_Send(p,a,b,c,d,e)              (p)->Send(a,b,c,d,e)
#define IDirectPlay3_SetGroupData(p,a,b,c,d)        (p)->SetGroupData(a,b,c,d)
#define IDirectPlay3_SetGroupName(p,a,b,c)          (p)->SetGroupName(a,b,c)
#define IDirectPlay3_SetPlayerData(p,a,b,c,d)       (p)->SetPlayerData(a,b,c,d)
#define IDirectPlay3_SetPlayerName(p,a,b,c)         (p)->SetPlayerName(a,b,c)
#define IDirectPlay3_SetSessionDesc(p,a,b)          (p)->SetSessionDesc(a,b)
#define IDirectPlay3_AddGroupToGroup(p,a,b) 		(p)->AddGroupToGroup(a,b)
#define IDirectPlay3_CreateGroupInGroup(p,a,b,c,d,e,f) (p)->CreateGroupInGroup(a,b,c,d,e,f)
#define IDirectPlay3_DeleteGroupFromGroup(p,a,b)   	(p)->DeleteGroupFromGroup(a,b)
#define IDirectPlay3_EnumConnections(p,a,b,c,d)     (p)->EnumConnections(a,b,c,d)
#define IDirectPlay3_EnumGroupsInGroup(p,a,b,c,d,e) (p)->EnumGroupsInGroup(a,b,c,d,e)
#define IDirectPlay3_GetGroupConnectionSettings(p,a,b,c,d) (p)->GetGroupConnectionSettings(a,b,c,d)
#define IDirectPlay3_InitializeConnection(p,a,b)    (p)->InitializeConnection(a,b)
#define IDirectPlay3_SecureOpen(p,a,b,c,d)          (p)->SecureOpen(a,b,c,d)
#define IDirectPlay3_SendChatMessage(p,a,b,c,d)     (p)->SendChatMessage(a,b,c,d)
#define IDirectPlay3_SetGroupConnectionSettings(p,a,b,c) (p)->SetGroupConnectionSettings(a,b,c)
#define IDirectPlay3_StartSession(p,a,b)            (p)->StartSession(a,b)
#define IDirectPlay3_GetGroupFlags(p,a,b)           (p)->GetGroupFlags(a,b)
#define IDirectPlay3_GetGroupParent(p,a,b)          (p)->GetGroupParent(a,b)
#define IDirectPlay3_GetPlayerAccount(p,a,b,c,d)    (p)->GetPlayerAccount(a,b,c,d)
#define IDirectPlay3_GetPlayerFlags(p,a,b)          (p)->GetPlayerFlags(a,b)

#endif

/****************************************************************************
 *
 * EnumConnections API flags
 *
 ****************************************************************************/

/*
 * Enumerate Service Providers
 */
#define DPCONNECTION_DIRECTPLAY      0x00000001

/*
 * Enumerate Lobby Providers
 */
#define DPCONNECTION_DIRECTPLAYLOBBY 0x00000002


/****************************************************************************
 *
 * EnumPlayers API flags
 *
 ****************************************************************************/

/*
 * Enumerate all players in the current session
 */
#define DPENUMPLAYERS_ALL           0x00000000
#define DPENUMGROUPS_ALL            DPENUMPLAYERS_ALL


/*
 * Enumerate only local (created by this application) players
 * or groups
 */
#define DPENUMPLAYERS_LOCAL         0x00000008
#define DPENUMGROUPS_LOCAL			DPENUMPLAYERS_LOCAL

/*
 * Enumerate only remote (non-local) players
 * or groups
 */
#define DPENUMPLAYERS_REMOTE        0x00000010
#define DPENUMGROUPS_REMOTE			DPENUMPLAYERS_REMOTE

/*
 * Enumerate groups along with the players
 */
#define DPENUMPLAYERS_GROUP         0x00000020

/*
 * Enumerate players or groups in another session 
 * (must supply lpguidInstance)
 */
#define DPENUMPLAYERS_SESSION       0x00000080
#define DPENUMGROUPS_SESSION		DPENUMPLAYERS_SESSION

/*
 * Enumerate server players
 */
#define DPENUMPLAYERS_SERVERPLAYER  0x00000100

/*
 * Enumerate spectator players
 */
#define DPENUMPLAYERS_SPECTATOR     0x00000200

/*
 * Enumerate shortcut groups
 */
#define DPENUMGROUPS_SHORTCUT       0x00000400

/*
 * Enumerate staging area groups
 */
#define DPENUMGROUPS_STAGINGAREA    0x00000800

/****************************************************************************
 *
 * CreatePlayer API flags
 *
 ****************************************************************************/

/*
 * This flag indicates that this player should be designated
 * the server player. The app should specify this at CreatePlayer.
 */
#define DPPLAYER_SERVERPLAYER           DPENUMPLAYERS_SERVERPLAYER

/*
 * This flag indicates that this player should be designated
 * a spectator. The app should specify this at CreatePlayer.
 */
#define DPPLAYER_SPECTATOR              DPENUMPLAYERS_SPECTATOR

/*
 * This flag indicates that this player was created locally.
 * (returned from GetPlayerFlags)
 */
#define DPPLAYER_LOCAL                  DPENUMPLAYERS_LOCAL

/****************************************************************************
 *
 * CreateGroup API flags
 *
 ****************************************************************************/


/*
 * This flag indicates that the StartSession can be called on the group.
 * The app should specify this at CreateGroup, or CreateGroupInGroup.
 */
#define DPGROUP_STAGINGAREA             DPENUMGROUPS_STAGINGAREA

/*
 * This flag indicates that this group was created locally.
 * (returned from GetGroupFlags)
 */
#define DPGROUP_LOCAL                   DPENUMGROUPS_LOCAL

/****************************************************************************
 *
 * EnumSessions API flags
 *
 ****************************************************************************/

/*
 * Enumerate sessions which can be joined
 */
#define DPENUMSESSIONS_AVAILABLE    0x00000001 

/*
 * Enumerate all sessions even if they can't be joined.
 */
#define DPENUMSESSIONS_ALL          0x00000002




/*
 * Start an asynchronous enum sessions
 */
 #define DPENUMSESSIONS_ASYNC		0x00000010

/*
 * Stop an asynchronous enum sessions
 */
 #define DPENUMSESSIONS_STOPASYNC	0x00000020
 
/*
 * Enumerate sessions even if they require a password
 */
 #define DPENUMSESSIONS_PASSWORDREQUIRED	0x00000040

/*
 * Return status about progress of enumeration instead of
 * showing any status dialogs.
 */
 #define DPENUMSESSIONS_RETURNSTATUS 0x00000080

/****************************************************************************
 *
 * GetCaps and GetPlayerCaps API flags
 *
 ****************************************************************************/

/*
 * The latency returned should be for guaranteed message sending.
 * Default is non-guaranteed messaging.
 */
#define DPGETCAPS_GUARANTEED        0x00000001 

 
/****************************************************************************
 *
 * GetGroupData, GetPlayerData API flags
 * Remote and local Group/Player data is maintained separately. 
 * Default is DPGET_REMOTE.
 *
 ****************************************************************************/

/*
 * Get the remote data (set by any DirectPlay object in
 * the session using DPSET_REMOTE)
 */
#define DPGET_REMOTE                0x00000000

/*
 * Get the local data (set by this DirectPlay object 
 * using DPSET_LOCAL)
 */
#define DPGET_LOCAL                 0x00000001


/****************************************************************************
 *
 * Open API flags
 *
 ****************************************************************************/

/*
 * Join the session that is described by the DPSESSIONDESC2 structure
 */
#define DPOPEN_JOIN                 0x00000001

/*
 * Create a new session as described by the DPSESSIONDESC2 structure
 */
#define DPOPEN_CREATE               0x00000002

/*
 * Return status about progress of open instead of showing
 * any status dialogs.
 */
 #define DPOPEN_RETURNSTATUS		DPENUMSESSIONS_RETURNSTATUS

/****************************************************************************
 *
 * DPLCONNECTION flags
 *
 ****************************************************************************/

/*
 * This application should create a new session as
 * described by the DPSESIONDESC structure
 */
#define DPLCONNECTION_CREATESESSION					DPOPEN_CREATE

/*
 * This application should join the session described by 
 * the DPSESIONDESC structure with the lpAddress data
 */
#define DPLCONNECTION_JOINSESSION					DPOPEN_JOIN

/****************************************************************************
 *
 * Receive API flags
 * Default is DPRECEIVE_ALL
 *
 ****************************************************************************/

/*
 * Get the first message in the queue
 */
#define DPRECEIVE_ALL               0x00000001

/*
 * Get the first message in the queue directed to a specific player 
 */
#define DPRECEIVE_TOPLAYER          0x00000002

/*
 * Get the first message in the queue from a specific player
 */
#define DPRECEIVE_FROMPLAYER        0x00000004

/*
 * Get the message but don't remove it from the queue
 */
#define DPRECEIVE_PEEK              0x00000008


/****************************************************************************
 *
 * Send API flags
 *
 ****************************************************************************/

/*
 * Send the message using a guaranteed send method.
 * Default is non-guaranteed.
 */
#define DPSEND_GUARANTEED           0x00000001


/*
 * This flag is obsolete. It is ignored by DirectPlay
 */
#define DPSEND_HIGHPRIORITY         0x00000002

/*
 * This flag is obsolete. It is ignored by DirectPlay
 */
#define DPSEND_OPENSTREAM           0x00000008

/*
 * This flag is obsolete. It is ignored by DirectPlay
 */
#define DPSEND_CLOSESTREAM          0x00000010

/*
 * Send the message digitally signed to ensure authenticity.
 */
#define DPSEND_SIGNED               0x00000020

/*
 * Send the message with encryption to ensure privacy.
 */
#define DPSEND_ENCRYPTED            0x00000040


/****************************************************************************
 *
 * SetGroupData, SetGroupName, SetPlayerData, SetPlayerName,
 * SetSessionDesc API flags.
 * Default is DPSET_REMOTE.
 *
 ****************************************************************************/

/* 
 * Propagate the data to all players in the session
 */
#define DPSET_REMOTE                0x00000000

/*
 * Do not propagate the data to other players
 */
#define DPSET_LOCAL                 0x00000001

/*
 * Used with DPSET_REMOTE, use guaranteed message send to
 * propagate the data
 */
#define DPSET_GUARANTEED            0x00000002


/****************************************************************************
 *
 * DirectPlay system messages and message data structures
 *
 * All system message come 'From' player DPID_SYSMSG.  To determine what type 
 * of message it is, cast the lpData from Receive to DPMSG_GENERIC and check
 * the dwType member against one of the following DPSYS_xxx constants. Once
 * a match is found, cast the lpData to the corresponding of the DPMSG_xxx
 * structures to access the data of the message.
 *
 ****************************************************************************/

/*
 * A new player or group has been created in the session
 * Use DPMSG_CREATEPLAYERORGROUP.  Check dwPlayerType to see if it
 * is a player or a group.
 */
#define DPSYS_CREATEPLAYERORGROUP   0x0003  

/*
 * A player has been deleted from the session
 * Use DPMSG_DESTROYPLAYERORGROUP
 */
#define DPSYS_DESTROYPLAYERORGROUP  0x0005  

/*
 * A player has been added to a group
 * Use DPMSG_ADDPLAYERTOGROUP
 */
#define DPSYS_ADDPLAYERTOGROUP      0x0007  

/*
 * A player has been removed from a group
 * Use DPMSG_DELETEPLAYERFROMGROUP
 */
#define DPSYS_DELETEPLAYERFROMGROUP 0x0021  

/*
 * This DirectPlay object lost its connection with all the
 * other players in the session.
 * Use DPMSG_SESSIONLOST.
 */
#define DPSYS_SESSIONLOST           0x0031

/*
 * The current host has left the session.
 * This DirectPlay object is now the host.
 * Use DPMSG_HOST.
 */
#define DPSYS_HOST                  0x0101

/*
 * The remote data associated with a player or
 * group has changed. Check dwPlayerType to see
 * if it is a player or a group
 * Use DPMSG_SETPLAYERORGROUPDATA
 */
#define DPSYS_SETPLAYERORGROUPDATA  0x0102

/*
 * The name of a player or group has changed.
 * Check dwPlayerType to see if it is a player
 * or a group.
 * Use DPMSG_SETPLAYERORGROUPNAME
 */
#define DPSYS_SETPLAYERORGROUPNAME  0x0103

/*
 * The session description has changed.
 * Use DPMSG_SETSESSIONDESC
 */
#define DPSYS_SETSESSIONDESC        0x0104

/*
 * A group has been added to a group
 * Use DPMSG_ADDGROUPTOGROUP
 */
#define DPSYS_ADDGROUPTOGROUP      	0x0105  

/*
 * A group has been removed from a group
 * Use DPMSG_DELETEGROUPFROMGROUP
 */
#define DPSYS_DELETEGROUPFROMGROUP 	0x0106

/*
 * A secure player-player message has arrived.
 * Use DPMSG_SECUREMESSAGE
 */
#define DPSYS_SECUREMESSAGE         0x0107

/*
 * Start a new session.
 * Use DPMSG_STARTSESSION
 */
#define DPSYS_STARTSESSION          0x0108

/*
 * A chat message has arrived
 * Use DPMSG_CHAT
 */
#define DPSYS_CHAT                  0x0109

/*
 * Used in the dwPlayerType field to indicate if it applies to a group
 * or a player
 */
#define DPPLAYERTYPE_GROUP          0x00000000
#define DPPLAYERTYPE_PLAYER         0x00000001


/*
 * DPMSG_GENERIC
 * Generic message structure used to identify the message type.
 */
typedef struct
{
    DWORD       dwType;         // Message type
} DPMSG_GENERIC, FAR *LPDPMSG_GENERIC;

/*
 * DPMSG_CREATEPLAYERORGROUP
 * System message generated when a new player or group
 * created in the session with information about it.
 */
typedef struct
{
    DWORD       dwType;         // Message type
    DWORD       dwPlayerType;   // Is it a player or group
    DPID        dpId;           // ID of the player or group
    DWORD       dwCurrentPlayers;   // current # players & groups in session
    LPVOID      lpData;         // pointer to remote data
    DWORD       dwDataSize;     // size of remote data
    DPNAME      dpnName;        // structure with name info
	// the following fields are only available when using
	// the IDirectPlay3 interface or greater
    DPID	    dpIdParent;     // id of parent group
	DWORD		dwFlags;		// player or group flags
} DPMSG_CREATEPLAYERORGROUP, FAR *LPDPMSG_CREATEPLAYERORGROUP;

/*
 * DPMSG_DESTROYPLAYERORGROUP
 * System message generated when a player or group is being
 * destroyed in the session with information about it.
 */
typedef struct
{
    DWORD       dwType;         // Message type
    DWORD       dwPlayerType;   // Is it a player or group
    DPID        dpId;           // player ID being deleted
    LPVOID      lpLocalData;    // copy of players local data
    DWORD       dwLocalDataSize; // sizeof local data
    LPVOID      lpRemoteData;   // copy of players remote data
    DWORD       dwRemoteDataSize; // sizeof remote data
	// the following fields are only available when using
	// the IDirectPlay3 interface or greater
    DPNAME      dpnName;        // structure with name info
    DPID	    dpIdParent;     // id of parent group	
	DWORD		dwFlags;		// player or group flags
} DPMSG_DESTROYPLAYERORGROUP, FAR *LPDPMSG_DESTROYPLAYERORGROUP;

/*
 * DPMSG_ADDPLAYERTOGROUP
 * System message generated when a player is being added
 * to a group.
 */
typedef struct
{
    DWORD       dwType;         // Message type
    DPID        dpIdGroup;      // group ID being added to
    DPID        dpIdPlayer;     // player ID being added
} DPMSG_ADDPLAYERTOGROUP, FAR *LPDPMSG_ADDPLAYERTOGROUP;

/*
 * DPMSG_DELETEPLAYERFROMGROUP
 * System message generated when a player is being
 * removed from a group
 */
typedef DPMSG_ADDPLAYERTOGROUP          DPMSG_DELETEPLAYERFROMGROUP;
typedef DPMSG_DELETEPLAYERFROMGROUP     FAR *LPDPMSG_DELETEPLAYERFROMGROUP;

/*
 * DPMSG_ADDGROUPTOGROUP
 * System message generated when a group is being added
 * to a group.
 */
typedef struct
{
    DWORD       dwType;         // Message type
    DPID        dpIdParentGroup; // group ID being added to
    DPID        dpIdGroup;     // group ID being added
} DPMSG_ADDGROUPTOGROUP, FAR *LPDPMSG_ADDGROUPTOGROUP;

/*
 * DPMSG_DELETEGROUPFROMGROUP
 * System message generated when a GROUP is being
 * removed from a group
 */
typedef DPMSG_ADDGROUPTOGROUP          DPMSG_DELETEGROUPFROMGROUP;
typedef DPMSG_DELETEGROUPFROMGROUP     FAR *LPDPMSG_DELETEGROUPFROMGROUP;

/*
 * DPMSG_SETPLAYERORGROUPDATA
 * System message generated when remote data for a player or
 * group has changed.
 */
typedef struct
{
    DWORD       dwType;         // Message type
    DWORD       dwPlayerType;   // Is it a player or group
    DPID        dpId;           // ID of player or group
    LPVOID      lpData;         // pointer to remote data
    DWORD       dwDataSize;     // size of remote data
} DPMSG_SETPLAYERORGROUPDATA, FAR *LPDPMSG_SETPLAYERORGROUPDATA;

/*
 * DPMSG_SETPLAYERORGROUPNAME
 * System message generated when the name of a player or
 * group has changed.
 */
typedef struct
{
    DWORD       dwType;         // Message type
    DWORD       dwPlayerType;   // Is it a player or group
    DPID        dpId;           // ID of player or group
    DPNAME      dpnName;        // structure with new name info
} DPMSG_SETPLAYERORGROUPNAME, FAR *LPDPMSG_SETPLAYERORGROUPNAME;

/*
 * DPMSG_SETSESSIONDESC
 * System message generated when session desc has changed
 */
typedef struct
{
    DWORD           dwType;     // Message type
    DPSESSIONDESC2  dpDesc;     // Session desc
} DPMSG_SETSESSIONDESC, FAR *LPDPMSG_SETSESSIONDESC;

/*
 * DPMSG_HOST
 * System message generated when the host has migrated to this
 * DirectPlay object.
 *
 */
typedef DPMSG_GENERIC       DPMSG_HOST;
typedef DPMSG_HOST          FAR *LPDPMSG_HOST;

/*
 * DPMSG_SESSIONLOST
 * System message generated when the connection to the session is lost.
 *
 */
typedef DPMSG_GENERIC       DPMSG_SESSIONLOST;
typedef DPMSG_SESSIONLOST   FAR *LPDPMSG_SESSIONLOST;

/*
 * DPMSG_SECUREMESSAGE
 * System message generated when a player requests a secure send
 */
typedef struct 
{
    DWORD		dwType;         // Message Type
    DWORD		dwFlags;        // Signed/Encrypted
    DPID        dpIdFrom;       // ID of Sending Player
    LPVOID		lpData;         // Player message
    DWORD		dwDataSize;     // Size of player message
} DPMSG_SECUREMESSAGE, FAR *LPDPMSG_SECUREMESSAGE;

/*
 * DPMSG_STARTSESSION
 * System message containing all information required to 
 * start a new session
 */
typedef struct
{
    DWORD              dwType;     // Message type
    LPDPLCONNECTION    lpConn;     // DPLCONNECTION structure
} DPMSG_STARTSESSION, FAR *LPDPMSG_STARTSESSION;

/*
 * DPMSG_CHAT
 * System message containing a chat message
 */
typedef struct
{
    DWORD              dwType;        // Message type
    DWORD              dwFlags;       // Message flags
    DPID               idFromPlayer;  // ID of the Sending Player
    DPID               idToPlayer;    // ID of the To Player
    DPID               idToGroup;     // ID of the To Group
    LPDPCHAT           lpChat;        // Pointer to a structure containing the chat message
} DPMSG_CHAT, FAR *LPDPMSG_CHAT;

/****************************************************************************
 *
 * DIRECTPLAY ERRORS
 *
 * Errors are represented by negative values and cannot be combined.
 *
 ****************************************************************************/
#define DP_OK                           S_OK
#define DPERR_ALREADYINITIALIZED        MAKE_DPHRESULT(   5 )
#define DPERR_ACCESSDENIED              MAKE_DPHRESULT(  10 )
#define DPERR_ACTIVEPLAYERS             MAKE_DPHRESULT(  20 )
#define DPERR_BUFFERTOOSMALL            MAKE_DPHRESULT(  30 )
#define DPERR_CANTADDPLAYER             MAKE_DPHRESULT(  40 )
#define DPERR_CANTCREATEGROUP           MAKE_DPHRESULT(  50 )
#define DPERR_CANTCREATEPLAYER          MAKE_DPHRESULT(  60 )
#define DPERR_CANTCREATESESSION         MAKE_DPHRESULT(  70 )
#define DPERR_CAPSNOTAVAILABLEYET       MAKE_DPHRESULT(  80 )
#define DPERR_EXCEPTION                 MAKE_DPHRESULT(  90 )
#define DPERR_GENERIC                   E_FAIL
#define DPERR_INVALIDFLAGS              MAKE_DPHRESULT( 120 )
#define DPERR_INVALIDOBJECT             MAKE_DPHRESULT( 130 )
#define DPERR_INVALIDPARAM              E_INVALIDARG
#define DPERR_INVALIDPARAMS             DPERR_INVALIDPARAM
#define DPERR_INVALIDPLAYER             MAKE_DPHRESULT( 150 )
#define DPERR_INVALIDGROUP             	MAKE_DPHRESULT( 155 )
#define DPERR_NOCAPS                    MAKE_DPHRESULT( 160 )
#define DPERR_NOCONNECTION              MAKE_DPHRESULT( 170 )
#define DPERR_NOMEMORY                  E_OUTOFMEMORY
#define DPERR_OUTOFMEMORY               DPERR_NOMEMORY
#define DPERR_NOMESSAGES                MAKE_DPHRESULT( 190 )
#define DPERR_NONAMESERVERFOUND         MAKE_DPHRESULT( 200 )
#define DPERR_NOPLAYERS                 MAKE_DPHRESULT( 210 )
#define DPERR_NOSESSIONS                MAKE_DPHRESULT( 220 )
#define DPERR_PENDING					E_PENDING
#define DPERR_SENDTOOBIG				MAKE_DPHRESULT( 230 )
#define DPERR_TIMEOUT                   MAKE_DPHRESULT( 240 )
#define DPERR_UNAVAILABLE               MAKE_DPHRESULT( 250 )
#define DPERR_UNSUPPORTED               E_NOTIMPL
#define DPERR_BUSY                      MAKE_DPHRESULT( 270 )
#define DPERR_USERCANCEL                MAKE_DPHRESULT( 280 ) 
#define DPERR_NOINTERFACE               E_NOINTERFACE
#define DPERR_CANNOTCREATESERVER        MAKE_DPHRESULT( 290 )
#define DPERR_PLAYERLOST                MAKE_DPHRESULT( 300 )
#define DPERR_SESSIONLOST               MAKE_DPHRESULT( 310 )
#define DPERR_UNINITIALIZED             MAKE_DPHRESULT( 320 )
#define DPERR_NONEWPLAYERS              MAKE_DPHRESULT( 330 )
#define DPERR_INVALIDPASSWORD           MAKE_DPHRESULT( 340 )
#define DPERR_CONNECTING                MAKE_DPHRESULT( 350 )


#define DPERR_BUFFERTOOLARGE            MAKE_DPHRESULT( 1000 )
#define DPERR_CANTCREATEPROCESS         MAKE_DPHRESULT( 1010 )
#define DPERR_APPNOTSTARTED             MAKE_DPHRESULT( 1020 )
#define DPERR_INVALIDINTERFACE          MAKE_DPHRESULT( 1030 )
#define DPERR_NOSERVICEPROVIDER         MAKE_DPHRESULT( 1040 )
#define DPERR_UNKNOWNAPPLICATION        MAKE_DPHRESULT( 1050 )
#define DPERR_NOTLOBBIED                MAKE_DPHRESULT( 1070 )
#define DPERR_SERVICEPROVIDERLOADED		MAKE_DPHRESULT( 1080 )
#define DPERR_ALREADYREGISTERED			MAKE_DPHRESULT( 1090 )
#define DPERR_NOTREGISTERED				MAKE_DPHRESULT( 1100 )

//
// Security related errors
//
#define DPERR_AUTHENTICATIONFAILED      MAKE_DPHRESULT(  2000 )
#define DPERR_CANTLOADSSPI              MAKE_DPHRESULT(  2010 )
#define DPERR_ENCRYPTIONFAILED          MAKE_DPHRESULT(  2020 )
#define DPERR_SIGNFAILED                MAKE_DPHRESULT(  2030 )
#define DPERR_CANTLOADSECURITYPACKAGE   MAKE_DPHRESULT(  2040 )
#define DPERR_ENCRYPTIONNOTSUPPORTED    MAKE_DPHRESULT(  2050 )
#define DPERR_CANTLOADCAPI              MAKE_DPHRESULT(  2060 )
#define DPERR_NOTLOGGEDIN               MAKE_DPHRESULT(  2070 )
#define DPERR_LOGONDENIED               MAKE_DPHRESULT(  2080 )


/****************************************************************************
 *
 * 	dplay 1.0 obsolete structures + interfaces
 *	Included for compatibility only. New apps should
 *	use IDirectPlay2
 *
 ****************************************************************************/

// define this to ignore obsolete interfaces and constants
#ifndef IDIRECTPLAY2_OR_GREATER

#define DPOPEN_OPENSESSION          DPOPEN_JOIN
#define DPOPEN_CREATESESSION        DPOPEN_CREATE

#define DPENUMSESSIONS_PREVIOUS     0x00000004

#define DPENUMPLAYERS_PREVIOUS      0x00000004

#define DPSEND_GUARANTEE            DPSEND_GUARANTEED
#define DPSEND_TRYONCE              0x00000004

#define DPCAPS_NAMESERVICE          0x00000001
#define DPCAPS_NAMESERVER           DPCAPS_ISHOST
#define DPCAPS_GUARANTEED           0x00000004

#define DPLONGNAMELEN               52
#define DPSHORTNAMELEN              20
#define DPSESSIONNAMELEN            32
#define DPPASSWORDLEN               16
#define DPUSERRESERVED              16

#define DPSYS_ADDPLAYER             0x0003
#define DPSYS_DELETEPLAYER          0x0005

#define DPSYS_DELETEGROUP           0x0020
#define DPSYS_DELETEPLAYERFROMGRP   0x0021
#define DPSYS_CONNECT               0x484b

typedef struct
{
    DWORD       dwType;
    DWORD       dwPlayerType;
    DPID        dpId;
    char        szLongName[DPLONGNAMELEN];
    char        szShortName[DPSHORTNAMELEN];
    DWORD       dwCurrentPlayers;
}   DPMSG_ADDPLAYER;

typedef DPMSG_ADDPLAYER DPMSG_ADDGROUP;

typedef struct
{
    DWORD       dwType;
    DPID        dpIdGroup;
    DPID        dpIdPlayer;
} DPMSG_GROUPADD;

typedef DPMSG_GROUPADD DPMSG_GROUPDELETE;
typedef struct
{
    DWORD       dwType;
    DPID        dpId;
} DPMSG_DELETEPLAYER;

typedef BOOL (PASCAL *LPDPENUMPLAYERSCALLBACK)(
    DPID    dpId,
    LPSTR   lpFriendlyName,
    LPSTR   lpFormalName,
    DWORD   dwFlags,
    LPVOID  lpContext );

typedef struct
{
    DWORD   dwSize;
    GUID    guidSession;                  
    DWORD   dwSession;                    
    DWORD   dwMaxPlayers;                 
    DWORD   dwCurrentPlayers;             
    DWORD   dwFlags;                      
    char    szSessionName[DPSESSIONNAMELEN];
    char    szUserField[DPUSERRESERVED];
    DWORD   dwReserved1;                  
    char    szPassword[DPPASSWORDLEN];    
    DWORD   dwReserved2;                  
    DWORD   dwUser1;
    DWORD   dwUser2;
    DWORD   dwUser3;
    DWORD   dwUser4;
} DPSESSIONDESC,*LPDPSESSIONDESC;

typedef BOOL (PASCAL * LPDPENUMSESSIONSCALLBACK)(
    LPDPSESSIONDESC lpDPSessionDesc,
    LPVOID      lpContext,
    LPDWORD     lpdwTimeOut,
    DWORD       dwFlags);

/*
 * IDirectPlay
 */
#undef INTERFACE
#define INTERFACE IDirectPlay
DECLARE_INTERFACE_( IDirectPlay, IUnknown )
{
    /*** IUnknown methods ***/
    STDMETHOD(QueryInterface)       (THIS_ REFIID riid, LPVOID * ppvObj) PURE;
    STDMETHOD_(ULONG,AddRef)        (THIS)  PURE;
    STDMETHOD_(ULONG,Release)       (THIS) PURE;
    /*** IDirectPlay methods ***/
    STDMETHOD(AddPlayerToGroup)     (THIS_ DPID, DPID) PURE;
    STDMETHOD(Close)                (THIS) PURE;
    STDMETHOD(CreatePlayer)         (THIS_ LPDPID,LPSTR,LPSTR,LPHANDLE) PURE;
    STDMETHOD(CreateGroup)          (THIS_ LPDPID,LPSTR,LPSTR) PURE;
    STDMETHOD(DeletePlayerFromGroup)(THIS_ DPID,DPID) PURE;
    STDMETHOD(DestroyPlayer)        (THIS_ DPID) PURE;
    STDMETHOD(DestroyGroup)         (THIS_ DPID) PURE;
    STDMETHOD(EnableNewPlayers)     (THIS_ BOOL) PURE;
    STDMETHOD(EnumGroupPlayers)     (THIS_ DPID, LPDPENUMPLAYERSCALLBACK,LPVOID,DWORD) PURE;
    STDMETHOD(EnumGroups)           (THIS_ DWORD, LPDPENUMPLAYERSCALLBACK,LPVOID,DWORD) PURE;
    STDMETHOD(EnumPlayers)          (THIS_ DWORD, LPDPENUMPLAYERSCALLBACK,LPVOID,DWORD) PURE;
    STDMETHOD(EnumSessions)         (THIS_ LPDPSESSIONDESC,DWORD,LPDPENUMSESSIONSCALLBACK,LPVOID,DWORD) PURE;
    STDMETHOD(GetCaps)              (THIS_ LPDPCAPS) PURE;
    STDMETHOD(GetMessageCount)      (THIS_ DPID, LPDWORD) PURE;
    STDMETHOD(GetPlayerCaps)        (THIS_ DPID, LPDPCAPS) PURE;
    STDMETHOD(GetPlayerName)        (THIS_ DPID,LPSTR,LPDWORD,LPSTR,LPDWORD) PURE;
    STDMETHOD(Initialize)           (THIS_ LPGUID) PURE;
    STDMETHOD(Open)                 (THIS_ LPDPSESSIONDESC) PURE;
    STDMETHOD(Receive)              (THIS_ LPDPID,LPDPID,DWORD,LPVOID,LPDWORD) PURE;
    STDMETHOD(SaveSession)          (THIS_ LPSTR) PURE;
    STDMETHOD(Send)                 (THIS_ DPID, DPID, DWORD, LPVOID, DWORD) PURE;
    STDMETHOD(SetPlayerName)        (THIS_ DPID,LPSTR,LPSTR) PURE;
};

/****************************************************************************
 *
 * IDirectPlay interface macros
 *
 ****************************************************************************/

#if !defined(__cplusplus) || defined(CINTERFACE)

#define IDirectPlay_AddPlayerToGroup(p,a,b)         (p)->lpVtbl->AddPlayerToGroup(p,a,b)
#define IDirectPlay_Close(p)                        (p)->lpVtbl->Close(p)
#define IDirectPlay_CreateGroup(p,a,b,c)            (p)->lpVtbl->CreateGroup(p,a,b,c)
#define IDirectPlay_CreatePlayer(p,a,b,c,d)         (p)->lpVtbl->CreatePlayer(p,a,b,c,d)
#define IDirectPlay_DeletePlayerFromGroup(p,a,b)    (p)->lpVtbl->DeletePlayerFromGroup(p,a,b)
#define IDirectPlay_DestroyGroup(p,a)               (p)->lpVtbl->DestroyGroup(p,a)
#define IDirectPlay_DestroyPlayer(p,a)              (p)->lpVtbl->DestroyPlayer(p,a)
#define IDirectPlay_EnableNewPlayers(p,a)           (p)->lpVtbl->EnableNewPlayers(p,a)
#define IDirectPlay_EnumGroupPlayers(p,a,b,c,d)     (p)->lpVtbl->EnumGroupPlayers(p,a,b,c,d)
#define IDirectPlay_EnumGroups(p,a,b,c,d)           (p)->lpVtbl->EnumGroups(p,a,b,c,d)
#define IDirectPlay_EnumPlayers(p,a,b,c,d)          (p)->lpVtbl->EnumPlayers(p,a,b,c,d)
#define IDirectPlay_EnumSessions(p,a,b,c,d,e)       (p)->lpVtbl->EnumSessions(p,a,b,c,d,e)
#define IDirectPlay_GetCaps(p,a)                    (p)->lpVtbl->GetCaps(p,a)
#define IDirectPlay_GetMessageCount(p,a,b)          (p)->lpVtbl->GetMessageCount(p,a,b)
#define IDirectPlay_GetPlayerCaps(p,a,b)            (p)->lpVtbl->GetPlayerCaps(p,a,b)
#define IDirectPlay_GetPlayerName(p,a,b,c,d,e)      (p)->lpVtbl->GetPlayerName(p,a,b,c,d,e)
#define IDirectPlay_Initialize(p,a)                 (p)->lpVtbl->Initialize(p,a)
#define IDirectPlay_Open(p,a)                       (p)->lpVtbl->Open(p,a)
#define IDirectPlay_Receive(p,a,b,c,d,e)            (p)->lpVtbl->Receive(p,a,b,c,d,e)
#define IDirectPlay_SaveSession(p,a)                (p)->lpVtbl->SaveSession(p,a)
#define IDirectPlay_Send(p,a,b,c,d,e)               (p)->lpVtbl->Send(p,a,b,c,d,e)
#define IDirectPlay_SetPlayerName(p,a,b,c)          (p)->lpVtbl->SetPlayerName(p,a,b,c)

#else /* C++ */

#define IDirectPlay_AddPlayerToGroup(p,a,b)         (p)->AddPlayerToGroup(a,b)
#define IDirectPlay_Close(p)                        (p)->Close()
#define IDirectPlay_CreateGroup(p,a,b,c)            (p)->CreateGroup(a,b,c)
#define IDirectPlay_CreatePlayer(p,a,b,c,d)         (p)->CreatePlayer(a,b,c,d)
#define IDirectPlay_DeletePlayerFromGroup(p,a,b)    (p)->DeletePlayerFromGroup(a,b)
#define IDirectPlay_DestroyGroup(p,a)               (p)->DestroyGroup(a)
#define IDirectPlay_DestroyPlayer(p,a)              (p)->DestroyPlayer(a)
#define IDirectPlay_EnableNewPlayers(p,a)           (p)->EnableNewPlayers(a)
#define IDirectPlay_EnumGroupPlayers(p,a,b,c,d)     (p)->EnumGroupPlayers(a,b,c,d)
#define IDirectPlay_EnumGroups(p,a,b,c,d)           (p)->EnumGroups(a,b,c,d)
#define IDirectPlay_EnumPlayers(p,a,b,c,d)          (p)->EnumPlayers(a,b,c,d)
#define IDirectPlay_EnumSessions(p,a,b,c,d,e)       (p)->EnumSessions(a,b,c,d,e)
#define IDirectPlay_GetCaps(p,a)                    (p)->GetCaps(a)
#define IDirectPlay_GetMessageCount(p,a,b)          (p)->GetMessageCount(a,b)
#define IDirectPlay_GetPlayerCaps(p,a,b)            (p)->GetPlayerCaps(a,b)
#define IDirectPlay_GetPlayerName(p,a,b,c,d,e)      (p)->GetPlayerName(a,b,c,d,e)
#define IDirectPlay_Initialize(p,a)                 (p)->Initialize(a)
#define IDirectPlay_Open(p,a)                       (p)->Open(a)
#define IDirectPlay_Receive(p,a,b,c,d,e)            (p)->Receive(a,b,c,d,e)
#define IDirectPlay_SaveSession(p,a)                (p)->SaveSession(a)
#define IDirectPlay_Send(p,a,b,c,d,e)               (p)->Send(a,b,c,d,e)
#define IDirectPlay_SetPlayerName(p,a,b,c)          (p)->SetPlayerName(a,b,c)

#endif

DEFINE_GUID(IID_IDirectPlay, 0x5454e9a0, 0xdb65, 0x11ce, 0x92, 0x1c, 0x00, 0xaa, 0x00, 0x6c, 0x49, 0x72);

#endif // IDIRECTPLAY2_OR_GREATER

/****************************************************************************
 *
 * IDirectPlay macros (included regardless of IDIRECTPLAY2_OR_GREATER flag)
 *
 ****************************************************************************/

#if !defined(__cplusplus) || defined(CINTERFACE)

#define IDirectPlay_QueryInterface(p,a,b)           (p)->lpVtbl->QueryInterface(p,a,b)
#define IDirectPlay_AddRef(p)                       (p)->lpVtbl->AddRef(p)
#define IDirectPlay_Release(p)                      (p)->lpVtbl->Release(p)

#else

#define IDirectPlay_QueryInterface(p,a,b)           (p)->QueryInterface(a,b)
#define IDirectPlay_AddRef(p)                       (p)->AddRef()
#define IDirectPlay_Release(p)                      (p)->Release()

#endif // IDirectPlay interface macros 

#ifdef __cplusplus
};
#endif

#endif
