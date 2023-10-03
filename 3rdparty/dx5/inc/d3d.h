/*==========================================================================;
 *
 *  Copyright (C) 1995-1997 Microsoft Corporation.  All Rights Reserved.
 *
 *  File:	d3d.h
 *  Content:	Direct3D include file
 *
 ***************************************************************************/

#ifndef _D3D_H_
#define _D3D_H_

#include <stdlib.h>

#ifdef _WIN32
#define COM_NO_WINDOWS_H
#include <objbase.h>
#else
#include "d3dcom.h"
#endif

#ifdef _WIN32
#define D3DAPI WINAPI
#else
#define D3DAPI
#endif

/*
 * Interface IID's
 */
#if defined( _WIN32 ) && !defined( _NO_COM)
DEFINE_GUID( IID_IDirect3D,             0x3BBA0080,0x2421,0x11CF,0xA3,0x1A,0x00,0xAA,0x00,0xB9,0x33,0x56 );
DEFINE_GUID( IID_IDirect3D2,            0x6aae1ec1,0x662a,0x11d0,0x88,0x9d,0x00,0xaa,0x00,0xbb,0xb7,0x6a);

DEFINE_GUID( IID_IDirect3DRampDevice,   0xF2086B20,0x259F,0x11CF,0xA3,0x1A,0x00,0xAA,0x00,0xB9,0x33,0x56 );
DEFINE_GUID( IID_IDirect3DRGBDevice,    0xA4665C60,0x2673,0x11CF,0xA3,0x1A,0x00,0xAA,0x00,0xB9,0x33,0x56 );
DEFINE_GUID( IID_IDirect3DHALDevice,    0x84E63dE0,0x46AA,0x11CF,0x81,0x6F,0x00,0x00,0xC0,0x20,0x15,0x6E );
DEFINE_GUID( IID_IDirect3DMMXDevice,    0x881949a1,0xd6f3,0x11d0,0x89,0xab,0x00,0xa0,0xc9,0x05,0x41,0x29 );

DEFINE_GUID( IID_IDirect3DDevice,		0x64108800,0x957d,0X11d0,0x89,0xab,0x00,0xa0,0xc9,0x05,0x41,0x29 );
DEFINE_GUID( IID_IDirect3DDevice2,	0x93281501, 0x8cf8, 0x11d0, 0x89, 0xab, 0x0, 0xa0, 0xc9, 0x5, 0x41, 0x29);
DEFINE_GUID( IID_IDirect3DTexture,      0x2CDCD9E0,0x25A0,0x11CF,0xA3,0x1A,0x00,0xAA,0x00,0xB9,0x33,0x56 );
DEFINE_GUID( IID_IDirect3DTexture2,	0x93281502, 0x8cf8, 0x11d0, 0x89, 0xab, 0x0, 0xa0, 0xc9, 0x5, 0x41, 0x29);
DEFINE_GUID( IID_IDirect3DLight,        0x4417C142,0x33AD,0x11CF,0x81,0x6F,0x00,0x00,0xC0,0x20,0x15,0x6E );
DEFINE_GUID( IID_IDirect3DMaterial,     0x4417C144,0x33AD,0x11CF,0x81,0x6F,0x00,0x00,0xC0,0x20,0x15,0x6E );
DEFINE_GUID( IID_IDirect3DMaterial2,	0x93281503, 0x8cf8, 0x11d0, 0x89, 0xab, 0x0, 0xa0, 0xc9, 0x5, 0x41, 0x29);
DEFINE_GUID( IID_IDirect3DExecuteBuffer,0x4417C145,0x33AD,0x11CF,0x81,0x6F,0x00,0x00,0xC0,0x20,0x15,0x6E );
DEFINE_GUID( IID_IDirect3DViewport,     0x4417C146,0x33AD,0x11CF,0x81,0x6F,0x00,0x00,0xC0,0x20,0x15,0x6E );
DEFINE_GUID( IID_IDirect3DViewport2,	0x93281500, 0x8cf8, 0x11d0, 0x89, 0xab, 0x0, 0xa0, 0xc9, 0x5, 0x41, 0x29);
#endif

/*
 * Data structures
 */
#ifdef __cplusplus

/* 'struct' not 'class' per the way DECLARE_INTERFACE_ is defined */
struct IDirect3D;
struct IDirect3D2;
struct IDirect3DDevice;
struct IDirect3DDevice2;
struct IDirect3DExecuteBuffer;
struct IDirect3DLight;
struct IDirect3DMaterial;
struct IDirect3DMaterial2;
struct IDirect3DTexture;
struct IDirect3DTexture2;
struct IDirect3DViewport;
struct IDirect3DViewport2;
typedef struct IDirect3D		*LPDIRECT3D;
typedef struct IDirect3D2		*LPDIRECT3D2;
typedef struct IDirect3DDevice		*LPDIRECT3DDEVICE;
typedef struct IDirect3DDevice2		*LPDIRECT3DDEVICE2;
typedef struct IDirect3DExecuteBuffer	*LPDIRECT3DEXECUTEBUFFER;
typedef struct IDirect3DLight		*LPDIRECT3DLIGHT;
typedef struct IDirect3DMaterial	*LPDIRECT3DMATERIAL;
typedef struct IDirect3DMaterial2	*LPDIRECT3DMATERIAL2;
typedef struct IDirect3DTexture		*LPDIRECT3DTEXTURE;
typedef struct IDirect3DTexture2		*LPDIRECT3DTEXTURE2;
typedef struct IDirect3DViewport	*LPDIRECT3DVIEWPORT;
typedef struct IDirect3DViewport2	*LPDIRECT3DVIEWPORT2;

#else

typedef struct IDirect3D		*LPDIRECT3D;
typedef struct IDirect3D2       *LPDIRECT3D2;
typedef struct IDirect3DDevice		*LPDIRECT3DDEVICE;
typedef struct IDirect3DDevice2		*LPDIRECT3DDEVICE2;
typedef struct IDirect3DExecuteBuffer	*LPDIRECT3DEXECUTEBUFFER;
typedef struct IDirect3DLight		*LPDIRECT3DLIGHT;
typedef struct IDirect3DMaterial	*LPDIRECT3DMATERIAL;
typedef struct IDirect3DMaterial2	*LPDIRECT3DMATERIAL2;
typedef struct IDirect3DTexture		*LPDIRECT3DTEXTURE;
typedef struct IDirect3DTexture2		*LPDIRECT3DTEXTURE2;
typedef struct IDirect3DViewport	*LPDIRECT3DVIEWPORT;
typedef struct IDirect3DViewport2	*LPDIRECT3DVIEWPORT2;

#endif

#include "d3dtypes.h"
#include "d3dcaps.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * IDirect3D
 */
#undef INTERFACE
#define INTERFACE IDirect3D
DECLARE_INTERFACE_(IDirect3D, IUnknown)
{
    /*** IUnknown methods ***/
    STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID* ppvObj) PURE;
    STDMETHOD_(ULONG, AddRef) (THIS) PURE;
    STDMETHOD_(ULONG, Release) (THIS) PURE;
    /*** IDirect3D methods ***/
    STDMETHOD(Initialize) (THIS_ REFIID) PURE;
    STDMETHOD(EnumDevices)(THIS_ LPD3DENUMDEVICESCALLBACK, LPVOID) PURE;
    STDMETHOD(CreateLight) (THIS_ LPDIRECT3DLIGHT*, IUnknown*) PURE;
    STDMETHOD(CreateMaterial) (THIS_ LPDIRECT3DMATERIAL*, IUnknown*) PURE;
    STDMETHOD(CreateViewport) (THIS_ LPDIRECT3DVIEWPORT*, IUnknown*) PURE;
    STDMETHOD(FindDevice)(THIS_ LPD3DFINDDEVICESEARCH, LPD3DFINDDEVICERESULT) PURE;
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IDirect3D_QueryInterface(p, a, b)         (p)->lpVtbl->QueryInterface(p, a, b)
#define IDirect3D_AddRef(p)                       (p)->lpVtbl->AddRef(p)
#define IDirect3D_Release(p)                      (p)->lpVtbl->Release(p)
#define IDirect3D_Initialize(p, a)                (p)->lpVtbl->Initialize(p, a)
#define IDirect3D_EnumDevices(p, a, b)            (p)->lpVtbl->EnumDevices(p, a, b)
#define IDirect3D_CreateLight(p, a, b)            (p)->lpVtbl->CreateLight(p, a, b)
#define IDirect3D_CreateMaterial(p, a, b)         (p)->lpVtbl->CreateMaterial(p, a, b)
#define IDirect3D_CreateViewport(p, a, b)         (p)->lpVtbl->CreateViewport(p, a, b)
#define IDirect3D_FindDevice(p, a, b)             (p)->lpVtbl->FindDevice(p, a, b)
#else
#define IDirect3D_QueryInterface(p, a, b)         (p)->QueryInterface(a, b)
#define IDirect3D_AddRef(p)                       (p)->AddRef()
#define IDirect3D_Release(p)                      (p)->Release()
#define IDirect3D_Initialize(p, a)                (p)->Initialize(a)
#define IDirect3D_EnumDevices(p, a, b)            (p)->EnumDevices(a, b)
#define IDirect3D_CreateLight(p, a, b)            (p)->CreateLight(a, b)
#define IDirect3D_CreateMaterial(p, a, b)         (p)->CreateMaterial(a, b)
#define IDirect3D_CreateViewport(p, a, b)         (p)->CreateViewport(a, b)
#define IDirect3D_FindDevice(p, a, b)             (p)->FindDevice(a, b)
#endif

/*
 * IDirect3D2
 */
#undef INTERFACE
#define INTERFACE IDirect3D2
DECLARE_INTERFACE_(IDirect3D2, IUnknown)
{
    /*** IUnknown methods ***/
    STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID* ppvObj) PURE;
    STDMETHOD_(ULONG, AddRef) (THIS) PURE;
    STDMETHOD_(ULONG, Release) (THIS) PURE;
    /*** IDirect3D methods ***/
    STDMETHOD(EnumDevices)(THIS_ LPD3DENUMDEVICESCALLBACK, LPVOID) PURE;
    STDMETHOD(CreateLight) (THIS_ LPDIRECT3DLIGHT*, IUnknown*) PURE;
    STDMETHOD(CreateMaterial) (THIS_ LPDIRECT3DMATERIAL2*, IUnknown*) PURE;
    STDMETHOD(CreateViewport) (THIS_ LPDIRECT3DVIEWPORT2*, IUnknown*) PURE;
    STDMETHOD(FindDevice)(THIS_ LPD3DFINDDEVICESEARCH, LPD3DFINDDEVICERESULT) PURE;

    STDMETHOD(CreateDevice)(THIS_ REFCLSID, LPDIRECTDRAWSURFACE, LPDIRECT3DDEVICE2 *) PURE;
 
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IDirect3D2_QueryInterface(p, a, b)         (p)->lpVtbl->QueryInterface(p, a, b)
#define IDirect3D2_AddRef(p)                       (p)->lpVtbl->AddRef(p)
#define IDirect3D2_Release(p)                      (p)->lpVtbl->Release(p)
#define IDirect3D2_EnumDevices(p, a, b)            (p)->lpVtbl->EnumDevices(p, a, b)
#define IDirect3D2_CreateLight(p, a, b)            (p)->lpVtbl->CreateLight(p, a, b)
#define IDirect3D2_CreateMaterial(p, a, b)         (p)->lpVtbl->CreateMaterial(p, a, b)
#define IDirect3D2_CreateViewport(p, a, b)         (p)->lpVtbl->CreateViewport(p, a, b)
#define IDirect3D2_FindDevice(p, a, b)             (p)->lpVtbl->FindDevice(p, a, b)
#define IDirect3D2_CreateDevice(p, a, b, c)		   (p)->lpVtbl->CreateDevice(p, a, b, c)
#else
#define IDirect3D2_QueryInterface(p, a, b)         (p)->QueryInterface(a, b)
#define IDirect3D2_AddRef(p)                       (p)->AddRef()
#define IDirect3D2_Release(p)                      (p)->Release()
#define IDirect3D2_EnumDevices(p, a, b)            (p)->EnumDevices(a, b)
#define IDirect3D2_CreateLight(p, a, b)            (p)->CreateLight(a, b)
#define IDirect3D2_CreateMaterial(p, a, b)         (p)->CreateMaterial(a, b)
#define IDirect3D2_CreateViewport(p, a, b)         (p)->CreateViewport(a, b)
#define IDirect3D2_FindDevice(p, a, b)             (p)->FindDevice(a, b)
#define IDirect3D2_CreateDevice(p, a, b, c)        (p)->CreateDevice(a, b, c)
#endif

/*
 * IDirect3DDevice
 */
#undef INTERFACE
#define INTERFACE IDirect3DDevice
DECLARE_INTERFACE_(IDirect3DDevice, IUnknown)
{
    /*** IUnknown methods ***/
    STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID* ppvObj) PURE;
    STDMETHOD_(ULONG, AddRef) (THIS) PURE;
    STDMETHOD_(ULONG, Release) (THIS) PURE;
    /*** IDirect3DDevice methods ***/
    STDMETHOD(Initialize) (THIS_ LPDIRECT3D, LPGUID, LPD3DDEVICEDESC) PURE;
    STDMETHOD(GetCaps) (THIS_ LPD3DDEVICEDESC, LPD3DDEVICEDESC) PURE;
    STDMETHOD(SwapTextureHandles) (THIS_ LPDIRECT3DTEXTURE, LPDIRECT3DTEXTURE) PURE;
    STDMETHOD(CreateExecuteBuffer) (THIS_ LPD3DEXECUTEBUFFERDESC, LPDIRECT3DEXECUTEBUFFER*, IUnknown*) PURE;
    STDMETHOD(GetStats) (THIS_ LPD3DSTATS) PURE;
    STDMETHOD(Execute) (THIS_ LPDIRECT3DEXECUTEBUFFER, LPDIRECT3DVIEWPORT, DWORD) PURE;
    STDMETHOD(AddViewport) (THIS_ LPDIRECT3DVIEWPORT) PURE;
    STDMETHOD(DeleteViewport) (THIS_ LPDIRECT3DVIEWPORT) PURE;
    STDMETHOD(NextViewport) (THIS_ LPDIRECT3DVIEWPORT, LPDIRECT3DVIEWPORT*, DWORD) PURE;
    STDMETHOD(Pick) (THIS_ LPDIRECT3DEXECUTEBUFFER, LPDIRECT3DVIEWPORT, DWORD, LPD3DRECT) PURE;
    STDMETHOD(GetPickRecords)(THIS_ LPDWORD, LPD3DPICKRECORD) PURE;
    STDMETHOD(EnumTextureFormats) (THIS_ LPD3DENUMTEXTUREFORMATSCALLBACK, LPVOID) PURE;
    STDMETHOD(CreateMatrix) (THIS_ LPD3DMATRIXHANDLE) PURE;
    STDMETHOD(SetMatrix) (THIS_ D3DMATRIXHANDLE, const LPD3DMATRIX) PURE;
    STDMETHOD(GetMatrix) (THIS_ D3DMATRIXHANDLE, LPD3DMATRIX) PURE;
    STDMETHOD(DeleteMatrix) (THIS_ D3DMATRIXHANDLE) PURE;
    STDMETHOD_(HRESULT, BeginScene) (THIS) PURE;
    STDMETHOD_(HRESULT, EndScene) (THIS) PURE;
    STDMETHOD(GetDirect3D) (THIS_ LPDIRECT3D*) PURE;
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IDirect3DDevice_QueryInterface(p, a, b)         (p)->lpVtbl->QueryInterface(p, a, b)
#define IDirect3DDevice_AddRef(p)                       (p)->lpVtbl->AddRef(p)
#define IDirect3DDevice_Release(p)                      (p)->lpVtbl->Release(p)
#define IDirect3DDevice_Initialize(p, a, b, c)          (p)->lpVtbl->Initialize(p, a, b, c)
#define IDirect3DDevice_GetCaps(p, a, b)                (p)->lpVtbl->GetCaps(p, a, b)
#define IDirect3DDevice_SwapTextureHandles(p, a, b)     (p)->lpVtbl->SwapTextureHandles(p, a, b)
#define IDirect3DDevice_CreateExecuteBuffer(p, a, b, c) (p)->lpVtbl->CreateExecuteBuffer(p, a, b, c)
#define IDirect3DDevice_GetStats(p, a)                  (p)->lpVtbl->GetStats(p, a)
#define IDirect3DDevice_Execute(p, a, b, c)             (p)->lpVtbl->Execute(p, a, b, c)
#define IDirect3DDevice_AddViewport(p, a)               (p)->lpVtbl->AddViewport(p, a)
#define IDirect3DDevice_DeleteViewport(p, a)            (p)->lpVtbl->DeleteViewport(p, a)
#define IDirect3DDevice_NextViewport(p, a, b)           (p)->lpVtbl->NextViewport(p, a, b)
#define IDirect3DDevice_Pick(p, a, b, c, d)             (p)->lpVtbl->Pick(p, a, b, c, d)
#define IDirect3DDevice_GetPickRecords(p, a, b)         (p)->lpVtbl->GetPickRecords(p, a, b)
#define IDirect3DDevice_EnumTextureFormats(p, a, b)     (p)->lpVtbl->EnumTextureFormats(p, a, b)
#define IDirect3DDevice_CreateMatrix(p, a)              (p)->lpVtbl->CreateMatrix(p, a)
#define IDirect3DDevice_SetMatrix(p, a, b)              (p)->lpVtbl->SetMatrix(p, a, b)
#define IDirect3DDevice_GetMatrix(p, a, b)              (p)->lpVtbl->GetMatrix(p, a, b)
#define IDirect3DDevice_DeleteMatrix(p, a)              (p)->lpVtbl->DeleteMatrix(p, a)
#define IDirect3DDevice_BeginScene(p)                   (p)->lpVtbl->BeginScene(p)
#define IDirect3DDevice_EndScene(p)                     (p)->lpVtbl->EndScene(p)
#define IDirect3DDevice_GetDirect3D(p, a)               (p)->lpVtbl->GetDirect3D(p, a)
#else
#define IDirect3DDevice_QueryInterface(p, a, b)         (p)->QueryInterface(a, b)
#define IDirect3DDevice_AddRef(p)                       (p)->AddRef()
#define IDirect3DDevice_Release(p)                      (p)->Release()
#define IDirect3DDevice_Initialize(p, a, b, c)          (p)->Initialize(a, b, c)
#define IDirect3DDevice_GetCaps(p, a, b)                (p)->GetCaps(a, b)
#define IDirect3DDevice_SwapTextureHandles(p, a, b)     (p)->SwapTextureHandles(a, b)
#define IDirect3DDevice_CreateExecuteBuffer(p, a, b, c) (p)->CreateExecuteBuffer(a, b, c)
#define IDirect3DDevice_GetStats(p, a)                  (p)->GetStats(a)
#define IDirect3DDevice_Execute(p, a, b, c)             (p)->Execute(a, b, c)
#define IDirect3DDevice_AddViewport(p, a)               (p)->AddViewport(a)
#define IDirect3DDevice_DeleteViewport(p, a)            (p)->DeleteViewport(a)
#define IDirect3DDevice_NextViewport(p, a, b)           (p)->NextViewport(a, b)
#define IDirect3DDevice_Pick(p, a, b, c, d)             (p)->Pick(a, b, c, d)
#define IDirect3DDevice_GetPickRecords(p, a, b)         (p)->GetPickRecords(a, b)
#define IDirect3DDevice_EnumTextureFormats(p, a, b)     (p)->EnumTextureFormats(a, b)
#define IDirect3DDevice_CreateMatrix(p, a)              (p)->CreateMatrix(a)
#define IDirect3DDevice_SetMatrix(p, a, b)              (p)->SetMatrix(a, b)
#define IDirect3DDevice_GetMatrix(p, a, b)              (p)->GetMatrix(a, b)
#define IDirect3DDevice_DeleteMatrix(p, a)              (p)->DeleteMatrix(a)
#define IDirect3DDevice_BeginScene(p)                   (p)->BeginScene()
#define IDirect3DDevice_EndScene(p)                     (p)->EndScene()
#define IDirect3DDevice_GetDirect3D(p, a)               (p)->GetDirect3D(a)
#endif

/*
 * IDirect3DDevice2
 */
#undef INTERFACE
#define INTERFACE IDirect3DDevice2
DECLARE_INTERFACE_(IDirect3DDevice2, IUnknown)
{
    /*** IUnknown methods ***/
    STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID* ppvObj) PURE;
    STDMETHOD_(ULONG, AddRef) (THIS) PURE;
    STDMETHOD_(ULONG, Release) (THIS) PURE;
    /*** IDirect3DDevice2 methods ***/
    STDMETHOD(GetCaps) (THIS_ LPD3DDEVICEDESC, LPD3DDEVICEDESC) PURE;
    STDMETHOD(SwapTextureHandles) (THIS_ LPDIRECT3DTEXTURE2, LPDIRECT3DTEXTURE2) PURE;
    STDMETHOD(GetStats) (THIS_ LPD3DSTATS) PURE;
    STDMETHOD(AddViewport) (THIS_ LPDIRECT3DVIEWPORT2) PURE;
    STDMETHOD(DeleteViewport) (THIS_ LPDIRECT3DVIEWPORT2) PURE;
    STDMETHOD(NextViewport) (THIS_ LPDIRECT3DVIEWPORT2, LPDIRECT3DVIEWPORT2*, DWORD) PURE;
    STDMETHOD(EnumTextureFormats) (THIS_ LPD3DENUMTEXTUREFORMATSCALLBACK, LPVOID) PURE;
    STDMETHOD_(HRESULT, BeginScene) (THIS) PURE;
    STDMETHOD_(HRESULT, EndScene) (THIS) PURE;
    STDMETHOD(GetDirect3D) (THIS_ LPDIRECT3D2*) PURE;

    /*** DrawPrimitive API ***/
    STDMETHOD(SetCurrentViewport) (THIS_ LPDIRECT3DVIEWPORT2) PURE;
    STDMETHOD(GetCurrentViewport) (THIS_ LPDIRECT3DVIEWPORT2 *) PURE;

    STDMETHOD(SetRenderTarget) (THIS_ LPDIRECTDRAWSURFACE, DWORD) PURE;
    STDMETHOD(GetRenderTarget) (THIS_ LPDIRECTDRAWSURFACE *) PURE;

    STDMETHOD(Begin) (THIS_ D3DPRIMITIVETYPE, D3DVERTEXTYPE, DWORD) PURE;
    STDMETHOD(BeginIndexed) (THIS_ D3DPRIMITIVETYPE, D3DVERTEXTYPE, LPVOID, DWORD, DWORD) PURE;
    STDMETHOD(Vertex) (THIS_ LPVOID) PURE;
    STDMETHOD(Index) (THIS_ WORD) PURE;
    STDMETHOD(End) (THIS_ DWORD) PURE;

    STDMETHOD(GetRenderState) (THIS_ D3DRENDERSTATETYPE, LPDWORD) PURE;
    STDMETHOD(SetRenderState) (THIS_ D3DRENDERSTATETYPE, DWORD) PURE;
    STDMETHOD(GetLightState) (THIS_ D3DLIGHTSTATETYPE, LPDWORD) PURE;
    STDMETHOD(SetLightState) (THIS_ D3DLIGHTSTATETYPE, DWORD) PURE;
    STDMETHOD(SetTransform) (THIS_ D3DTRANSFORMSTATETYPE, LPD3DMATRIX) PURE;
    STDMETHOD(GetTransform) (THIS_ D3DTRANSFORMSTATETYPE, LPD3DMATRIX) PURE;
    STDMETHOD(MultiplyTransform) (THIS_ D3DTRANSFORMSTATETYPE, LPD3DMATRIX) PURE;

    STDMETHOD(DrawPrimitive) (THIS_ D3DPRIMITIVETYPE, D3DVERTEXTYPE, LPVOID, DWORD, DWORD) PURE;
    STDMETHOD(DrawIndexedPrimitive) (THIS_ D3DPRIMITIVETYPE, D3DVERTEXTYPE, LPVOID, DWORD, LPWORD, DWORD, DWORD) PURE;

    STDMETHOD(SetClipStatus) (THIS_ LPD3DCLIPSTATUS) PURE;
    STDMETHOD(GetClipStatus) (THIS_ LPD3DCLIPSTATUS) PURE;
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IDirect3DDevice2_QueryInterface(p, a, b)         (p)->lpVtbl->QueryInterface(p, a, b)
#define IDirect3DDevice2_AddRef(p)                       (p)->lpVtbl->AddRef(p)
#define IDirect3DDevice2_Release(p)                      (p)->lpVtbl->Release(p)
#define IDirect3DDevice2_GetCaps(p, a, b)                (p)->lpVtbl->GetCaps(p, a, b)
#define IDirect3DDevice2_SwapTextureHandles(p, a, b)     (p)->lpVtbl->SwapTextureHandles(p, a, b)
#define IDirect3DDevice2_GetStats(p, a)                  (p)->lpVtbl->CreateViewport(p, a)
#define IDirect3DDevice2_AddViewport(p, a)               (p)->lpVtbl->AddViewport(p, a)
#define IDirect3DDevice2_DeleteViewport(p, a)            (p)->lpVtbl->DeleteViewport(p, a)
#define IDirect3DDevice2_NextViewport(p, a, b)           (p)->lpVtbl->NextViewport(p, a, b)
#define IDirect3DDevice2_EnumTextureFormats(p, a, b)     (p)->lpVtbl->EnumTextureFormats(p, a, b)
#define IDirect3DDevice2_BeginScene(p)                   (p)->lpVtbl->BeginScene(p)
#define IDirect3DDevice2_EndScene(p)                     (p)->lpVtbl->EndScene(p)
#define IDirect3DDevice2_GetDirect3D(p, a)               (p)->lpVtbl->GetDirect3D(p, a)

#define IDirect3DDevice2_SetCurrentViewport(p, a)        (p)->lpVtbl->SetCurrentViewport(p, a)
#define IDirect3DDevice2_GetCurrentViewport(p, a)        (p)->lpVtbl->GetCurrentViewport(p, a)

#define IDirect3DDevice2_SetRenderTarget(p, a, b)        (p)->lpVtbl->SetRenderTarget(p, a, b)
#define IDirect3DDevice2_GetRenderTarget(p, a)			 (p)->lpVtbl->GetRenderTarget(p, a)

#define IDirect3DDevice2_Begin(p, a, b, c)               (p)->lpVtbl->Begin(p, a, b, c)
#define IDirect3DDevice2_BeginIndexed(p, a, b, c, d, e)  (p)->lpVtbl->Begin(p, a, b, c, d, e)
#define IDirect3DDevice2_Vertex(p, a)                    (p)->lpVtbl->Vertex(p, a)
#define IDirect3DDevice2_Index(p, a)                     (p)->lpVtbl->Index(p, a)
#define IDirect3DDevice2_End(p, a)                       (p)->lpVtbl->End(p, a)

#define IDirect3DDevice2_GetRenderState(p, a, b)         (p)->lpVtbl->GetRenderState(p, a, b)
#define IDirect3DDevice2_SetRenderState(p, a, b)         (p)->lpVtbl->SetRenderState(p, a, b)
#define IDirect3DDevice2_GetLightState(p, a, b)          (p)->lpVtbl->GetLightState(p, a, b)
#define IDirect3DDevice2_SetLightState(p, a, b)          (p)->lpVtbl->SetLightState(p, a, b)
#define IDirect3DDevice2_SetTransform(p, a, b)           (p)->lpVtbl->SetTransform(p, a, b)
#define IDirect3DDevice2_GetTransform(p, a, b)           (p)->lpVtbl->GetTransform(p, a, b)
#define IDirect3DDevice2_MultiplyTransform(p, a, b)      (p)->lpVtbl->MultiplyTransform(p, a, b)

#define IDirect3DDevice2_DrawPrimitive(p, a, b, c, d, e) (p)->lpVtbl->DrawPrimitive(p, a, b, c, d, e)
#define IDirect3DDevice2_DrawIndexedPrimitive(p, a, b, c, d, e, f, g) \
                                                         (p)->lpVtbl->DrawIndexedPrimitive(p, a, b, c, d, e, f, g)
#define IDirect3DDevice2_SetClipStatus(p, a)				 (p)->lpVtbl->SetClipStatus(p, a)
#define IDirect3DDevice2_GetClipStatus(p, a)				 (p)->lpVtbl->GetClipStatus(p, a)
#else
#define IDirect3DDevice2_QueryInterface(p, a, b)         (p)->QueryInterface(a, b)
#define IDirect3DDevice2_AddRef(p)                       (p)->AddRef()
#define IDirect3DDevice2_Release(p)                      (p)->Release()
#define IDirect3DDevice2_GetCaps(p, a, b)                (p)->GetCaps(a, b)
#define IDirect3DDevice2_SwapTextureHandles(p, a, b)     (p)->SwapTextureHandles(a, b)
#define IDirect3DDevice2_GetStats(p, a)                  (p)->CreateViewport(a)
#define IDirect3DDevice2_AddViewport(p, a)               (p)->AddViewport(a)
#define IDirect3DDevice2_DeleteViewport(p, a)            (p)->DeleteViewport(a)
#define IDirect3DDevice2_NextViewport(p, a, b)           (p)->NextViewport(a, b)
#define IDirect3DDevice2_EnumTextureFormats(p, a, b)     (p)->EnumTextureFormats(a, b)
#define IDirect3DDevice2_BeginScene(p)                   (p)->BeginScene()
#define IDirect3DDevice2_EndScene(p)                     (p)->EndScene()
#define IDirect3DDevice2_GetDirect3D(p, a)               (p)->GetDirect3D(a)

#define IDirect3DDevice2_SetCurrentViewport(p, a)        (p)->SetCurrentViewport(a)
#define IDirect3DDevice2_GetCurrentViewport(p, a)        (p)->GetCurrentViewport(a)

#define IDirect3DDevice2_SetRenderTarget(p, a, b)        (p)->SetRenderTarget(a, b)
#define IDirect3DDevice2_GetRenderTarget(p, a)           (p)->GetRenderTarget(a)

#define IDirect3DDevice2_Begin(p, a, b, c)               (p)->Begin(a, b, c)
#define IDirect3DDevice2_BeginIndexed(p, a, b, c, d, e)  (p)->Begin(a, b, c, d, e)
#define IDirect3DDevice2_Vertex(p, a)                    (p)->Vertex(a)
#define IDirect3DDevice2_Index(p, a)                     (p)->Index(a)
#define IDirect3DDevice2_End(p, a)                       (p)->End(a)

#define IDirect3DDevice2_GetRenderState(p, a, b)         (p)->GetRenderState(a, b)
#define IDirect3DDevice2_SetRenderState(p, a, b)         (p)->SetRenderState(a, b)
#define IDirect3DDevice2_GetLightState(p, a, b)          (p)->GetLightState(a, b)
#define IDirect3DDevice2_SetLightState(p, a, b)          (p)->SetLightState(a, b)
#define IDirect3DDevice2_SetTransform(p, a, b)           (p)->SetTransform(a, b)
#define IDirect3DDevice2_GetTransform(p, a, b)           (p)->GetTransform(a, b)
#define IDirect3DDevice2_MultiplyTransform(p, a, b)      (p)->MultiplyTransform(a, b)

#define IDirect3DDevice2_DrawPrimitive(p, a, b, c, d, e) (p)->DrawPrimitive(a, b, c, d, e)
#define IDirect3DDevice2_DrawIndexedPrimitive(p, a, b, c, d, e, f, g) \
                                                         (p)->DrawIndexedPrimitive(a, b, c, d, e, f, g)
#define IDirect3DDevice2_SetClipStatus(p, a)                             (p)->SetClipStatus(a)
#define IDirect3DDevice2_GetClipStatus(p, a)                             (p)->GetClipStatus(a)

#endif

/*
 * IDirect3DExecuteBuffer
 */
#undef INTERFACE
#define INTERFACE IDirect3DExecuteBuffer
DECLARE_INTERFACE_(IDirect3DExecuteBuffer, IUnknown)
{
    /*** IUnknown methods ***/
    STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID* ppvObj) PURE;
    STDMETHOD_(ULONG, AddRef) (THIS) PURE;
    STDMETHOD_(ULONG, Release) (THIS) PURE;
    /*** IDirect3DExecuteBuffer methods ***/
    STDMETHOD(Initialize) (THIS_ LPDIRECT3DDEVICE, LPD3DEXECUTEBUFFERDESC) PURE;
    STDMETHOD(Lock) (THIS_ LPD3DEXECUTEBUFFERDESC) PURE;
    STDMETHOD_(HRESULT, Unlock) (THIS) PURE;
    STDMETHOD(SetExecuteData) (THIS_ LPD3DEXECUTEDATA) PURE;
    STDMETHOD(GetExecuteData) (THIS_ LPD3DEXECUTEDATA) PURE;
    STDMETHOD(Validate) (THIS_ LPDWORD, LPD3DVALIDATECALLBACK, LPVOID, DWORD) PURE;
    STDMETHOD(Optimize) (THIS_ DWORD) PURE;
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IDirect3DExecuteBuffer_QueryInterface(p, a, b) (p)->lpVtbl->QueryInterface(p, a, b)
#define IDirect3DExecuteBuffer_AddRef(p)               (p)->lpVtbl->AddRef(p)
#define IDirect3DExecuteBuffer_Release(p)              (p)->lpVtbl->Release(p)
#define IDirect3DExecuteBuffer_Initialize(p, a, b)     (p)->lpVtbl->Initialize(p, a, b)
#define IDirect3DExecuteBuffer_Lock(p, a)              (p)->lpVtbl->Lock(p, a)
#define IDirect3DExecuteBuffer_Unlock(p)               (p)->lpVtbl->Unlock(p)
#define IDirect3DExecuteBuffer_SetExecuteData(p, a)    (p)->lpVtbl->SetExecuteData(p, a)
#define IDirect3DExecuteBuffer_GetExecuteData(p, a)    (p)->lpVtbl->GetExecuteData(p, a)
#define IDirect3DExecuteBuffer_Validate(p, a, b, c, d) (p)->lpVtbl->Validate(p, a, b, c, d)
#define IDirect3DExecuteBuffer_Optimize(p, a)          (p)->lpVtbl->Optimize(p, a)
#else
#define IDirect3DExecuteBuffer_QueryInterface(p, a, b) (p)->QueryInterface(a, b)
#define IDirect3DExecuteBuffer_AddRef(p)               (p)->AddRef()
#define IDirect3DExecuteBuffer_Release(p)              (p)->Release()
#define IDirect3DExecuteBuffer_Initialize(p, a, b)     (p)->Initialize(a, b)
#define IDirect3DExecuteBuffer_Lock(p, a)              (p)->Lock(a)
#define IDirect3DExecuteBuffer_Unlock(p)               (p)->Unlock()
#define IDirect3DExecuteBuffer_SetExecuteData(p, a)    (p)->SetExecuteData(a)
#define IDirect3DExecuteBuffer_GetExecuteData(p, a)    (p)->GetExecuteData(a)
#define IDirect3DExecuteBuffer_Validate(p, a, b, c, d) (p)->Validate(a, b, c, d)
#define IDirect3DExecuteBuffer_Optimize(p, a)          (p)->Optimize(a)
#endif

/*
 * IDirect3DLight
 */
#undef INTERFACE
#define INTERFACE IDirect3DLight
DECLARE_INTERFACE_(IDirect3DLight, IUnknown)
{
    /*** IUnknown methods ***/
    STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID* ppvObj) PURE;
    STDMETHOD_(ULONG, AddRef) (THIS) PURE;
    STDMETHOD_(ULONG, Release) (THIS) PURE;
    /*** IDirect3DLight methods ***/
    STDMETHOD(Initialize) (THIS_ LPDIRECT3D) PURE;
    STDMETHOD(SetLight) (THIS_ LPD3DLIGHT) PURE;
    STDMETHOD(GetLight) (THIS_ LPD3DLIGHT) PURE;
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IDirect3DLight_QueryInterface(p, a, b) (p)->lpVtbl->QueryInterface(p, a, b)
#define IDirect3DLight_AddRef(p)               (p)->lpVtbl->AddRef(p)
#define IDirect3DLight_Release(p)              (p)->lpVtbl->Release(p)
#define IDirect3DLight_Initialize(p, a)        (p)->lpVtbl->Initialize(p, a)
#define IDirect3DLight_SetLight(p, a)          (p)->lpVtbl->SetLight(p, a)
#define IDirect3DLight_GetLight(p, a)          (p)->lpVtbl->GetLight(p, a)
#else
#define IDirect3DLight_QueryInterface(p, a, b) (p)->QueryInterface(a, b)
#define IDirect3DLight_AddRef(p)               (p)->AddRef()
#define IDirect3DLight_Release(p)              (p)->Release()
#define IDirect3DLight_Initialize(p, a)        (p)->Initialize(a)
#define IDirect3DLight_SetLight(p, a)          (p)->SetLight(a)
#define IDirect3DLight_GetLight(p, a)          (p)->GetLight(a)
#endif

/*
 * IDirect3DMaterial
 */
#undef INTERFACE
#define INTERFACE IDirect3DMaterial
DECLARE_INTERFACE_(IDirect3DMaterial, IUnknown)
{
    /*** IUnknown methods ***/
    STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID* ppvObj) PURE;
    STDMETHOD_(ULONG, AddRef) (THIS) PURE;
    STDMETHOD_(ULONG, Release) (THIS) PURE;
    /*** IDirect3DMaterial methods ***/
    STDMETHOD(Initialize) (THIS_ LPDIRECT3D) PURE;
    STDMETHOD(SetMaterial) (THIS_ LPD3DMATERIAL) PURE;
    STDMETHOD(GetMaterial) (THIS_ LPD3DMATERIAL) PURE;
    STDMETHOD(GetHandle) (THIS_ LPDIRECT3DDEVICE, LPD3DMATERIALHANDLE) PURE;
    STDMETHOD_(HRESULT, Reserve) (THIS) PURE;
    STDMETHOD_(HRESULT, Unreserve) (THIS) PURE;
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IDirect3DMaterial_QueryInterface(p, a, b) (p)->lpVtbl->QueryInterface(p, a, b)
#define IDirect3DMaterial_AddRef(p)               (p)->lpVtbl->AddRef(p)
#define IDirect3DMaterial_Release(p)              (p)->lpVtbl->Release(p)
#define IDirect3DMaterial_Initialize(p, a)        (p)->lpVtbl->Initialize(p, a)
#define IDirect3DMaterial_SetMaterial(p, a)       (p)->lpVtbl->SetMaterial(p, a)
#define IDirect3DMaterial_GetMaterial(p, a)       (p)->lpVtbl->GetMaterial(p, a)
#define IDirect3DMaterial_GetHandle(p, a, b)      (p)->lpVtbl->GetHandle(p, a, b)
#define IDirect3DMaterial_Reserve(p)              (p)->lpVtbl->Reserve(p)
#define IDirect3DMaterial_Unreserve(p)            (p)->lpVtbl->Unreserve(p)
#else
#define IDirect3DMaterial_QueryInterface(p, a, b) (p)->QueryInterface(a, b)
#define IDirect3DMaterial_AddRef(p)               (p)->AddRef()
#define IDirect3DMaterial_Release(p)              (p)->Release()
#define IDirect3DMaterial_Initialize(p, a)        (p)->Initialize(a)
#define IDirect3DMaterial_SetMaterial(p, a)       (p)->SetMaterial(a)
#define IDirect3DMaterial_GetMaterial(p, a)       (p)->GetMaterial(a)
#define IDirect3DMaterial_GetHandle(p, a, b)      (p)->GetHandle(a, b)
#define IDirect3DMaterial_Reserve(p)              (p)->Reserve()
#define IDirect3DMaterial_Unreserve(p)            (p)->Unreserve()
#endif

/*
 * IDirect3DMaterial2
 */
#undef INTERFACE
#define INTERFACE IDirect3DMaterial2
DECLARE_INTERFACE_(IDirect3DMaterial2, IUnknown)
{
    /*** IUnknown methods ***/
    STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID* ppvObj) PURE;
    STDMETHOD_(ULONG, AddRef) (THIS) PURE;
    STDMETHOD_(ULONG, Release) (THIS) PURE;
    /*** IDirect3DMaterial2 methods ***/
    STDMETHOD(SetMaterial) (THIS_ LPD3DMATERIAL) PURE;
    STDMETHOD(GetMaterial) (THIS_ LPD3DMATERIAL) PURE;
    STDMETHOD(GetHandle) (THIS_ LPDIRECT3DDEVICE2, LPD3DMATERIALHANDLE) PURE;
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IDirect3DMaterial2_QueryInterface(p, a, b) (p)->lpVtbl->QueryInterface(p, a, b)
#define IDirect3DMaterial2_AddRef(p)               (p)->lpVtbl->AddRef(p)
#define IDirect3DMaterial2_Release(p)              (p)->lpVtbl->Release(p)
#define IDirect3DMaterial2_SetMaterial(p, a)       (p)->lpVtbl->SetMaterial(p, a)
#define IDirect3DMaterial2_GetMaterial(p, a)       (p)->lpVtbl->GetMaterial(p, a)
#define IDirect3DMaterial2_GetHandle(p, a, b)      (p)->lpVtbl->GetHandle(p, a, b)
#else
#define IDirect3DMaterial2_QueryInterface(p, a, b) (p)->QueryInterface(a, b)
#define IDirect3DMaterial2_AddRef(p)               (p)->AddRef()
#define IDirect3DMaterial2_Release(p)              (p)->Release()
#define IDirect3DMaterial2_SetMaterial(p, a)       (p)->SetMaterial(a)
#define IDirect3DMaterial2_GetMaterial(p, a)       (p)->GetMaterial(a)
#define IDirect3DMaterial2_GetHandle(p, a, b)      (p)->GetHandle(a, b)
#endif

/*
 * IDirect3DTexture
 */
#undef INTERFACE
#define INTERFACE IDirect3DTexture
DECLARE_INTERFACE_(IDirect3DTexture, IUnknown)
{
    /*** IUnknown methods ***/
    STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID* ppvObj) PURE;
    STDMETHOD_(ULONG, AddRef) (THIS) PURE;
    STDMETHOD_(ULONG, Release) (THIS) PURE;
    /*** IDirect3DTexture methods ***/
    STDMETHOD(Initialize) (THIS_ LPDIRECT3DDEVICE, LPDIRECTDRAWSURFACE) PURE;
    STDMETHOD(GetHandle) (THIS_ LPDIRECT3DDEVICE, LPD3DTEXTUREHANDLE) PURE;
    STDMETHOD(PaletteChanged) (THIS_ DWORD, DWORD) PURE;
    STDMETHOD(Load) (THIS_ LPDIRECT3DTEXTURE) PURE;
    STDMETHOD_(HRESULT, Unload) (THIS) PURE;
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IDirect3DTexture_QueryInterface(p, a, b) (p)->lpVtbl->QueryInterface(p, a, b)
#define IDirect3DTexture_AddRef(p)               (p)->lpVtbl->AddRef(p)
#define IDirect3DTexture_Release(p)              (p)->lpVtbl->Release(p)
#define IDirect3DTexture_Initialize(p, a, b)     (p)->lpVtbl->Initialize(p, a, b)
#define IDirect3DTexture_GetHandle(p, a, b)      (p)->lpVtbl->GetHandle(p, a, b)
#define IDirect3DTexture_PaletteChanged(p, a, b) (p)->lpVtbl->PaletteChanged(p, a, b)
#define IDirect3DTexture_Load(p, a)              (p)->lpVtbl->Load(p, a)
#define IDirect3DTexture_Unload(p)               (p)->lpVtbl->Unload(p)
#else
#define IDirect3DTexture_QueryInterface(p, a, b) (p)->QueryInterface(a, b)
#define IDirect3DTexture_AddRef(p)               (p)->AddRef()
#define IDirect3DTexture_Release(p)              (p)->Release()
#define IDirect3DTexture_Initialize(p, a, b)     (p)->Initialize(a, b)
#define IDirect3DTexture_GetHandle(p, a, b)      (p)->GetHandle(a, b)
#define IDirect3DTexture_PaletteChanged(p, a, b) (p)->PaletteChanged(a, b)
#define IDirect3DTexture_Load(p, a)              (p)->Load(a)
#define IDirect3DTexture_Unload(p)               (p)->Unload()
#endif

/*
 * IDirect3DTexture2
 */
#undef INTERFACE
#define INTERFACE IDirect3DTexture2
DECLARE_INTERFACE_(IDirect3DTexture2, IUnknown)
{
    /*** IUnknown methods ***/
    STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID* ppvObj) PURE;
    STDMETHOD_(ULONG, AddRef) (THIS) PURE;
    STDMETHOD_(ULONG, Release) (THIS) PURE;
    /*** IDirect3DTexture2 methods ***/
    STDMETHOD(GetHandle) (THIS_ LPDIRECT3DDEVICE2, LPD3DTEXTUREHANDLE) PURE;
    STDMETHOD(PaletteChanged) (THIS_ DWORD, DWORD) PURE;
    STDMETHOD(Load) (THIS_ LPDIRECT3DTEXTURE2) PURE;
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IDirect3DTexture2_QueryInterface(p, a, b) (p)->lpVtbl->QueryInterface(p, a, b)
#define IDirect3DTexture2_AddRef(p)               (p)->lpVtbl->AddRef(p)
#define IDirect3DTexture2_Release(p)              (p)->lpVtbl->Release(p)
#define IDirect3DTexture2_GetHandle(p, a, b)      (p)->lpVtbl->GetHandle(p, a, b)
#define IDirect3DTexture2_PaletteChanged(p, a, b) (p)->lpVtbl->PaletteChanged(p, a, b)
#define IDirect3DTexture2_Load(p, a)              (p)->lpVtbl->Load(p, a)
#else
#define IDirect3DTexture2_QueryInterface(p, a, b) (p)->QueryInterface(a, b)
#define IDirect3DTexture2_AddRef(p)               (p)->AddRef()
#define IDirect3DTexture2_Release(p)              (p)->Release()
#define IDirect3DTexture2_GetHandle(p, a, b)      (p)->GetHandle(a, b)
#define IDirect3DTexture2_PaletteChanged(p, a, b) (p)->PaletteChanged(a, b)
#define IDirect3DTexture2_Load(p, a)              (p)->Load(a)
#endif

/* 
 * IDirect3DViewport
 */
#undef INTERFACE
#define INTERFACE IDirect3DViewport
DECLARE_INTERFACE_(IDirect3DViewport, IUnknown)
{
    /*** IUnknown methods ***/
    STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID* ppvObj) PURE;
    STDMETHOD_(ULONG, AddRef) (THIS) PURE;
    STDMETHOD_(ULONG, Release) (THIS) PURE;
    /*** IDirect3DViewport methods ***/
    STDMETHOD(Initialize) (THIS_ LPDIRECT3D) PURE;
    STDMETHOD(GetViewport) (THIS_ LPD3DVIEWPORT) PURE;
    STDMETHOD(SetViewport) (THIS_ LPD3DVIEWPORT) PURE;
    STDMETHOD(TransformVertices) (THIS_ DWORD, LPD3DTRANSFORMDATA, DWORD, LPDWORD) PURE;
    STDMETHOD(LightElements) (THIS_ DWORD, LPD3DLIGHTDATA) PURE;
    STDMETHOD(SetBackground) (THIS_ D3DMATERIALHANDLE) PURE;
    STDMETHOD(GetBackground) (THIS_ LPD3DMATERIALHANDLE, LPBOOL) PURE;
    STDMETHOD(SetBackgroundDepth) (THIS_ LPDIRECTDRAWSURFACE) PURE;
    STDMETHOD(GetBackgroundDepth) (THIS_ LPDIRECTDRAWSURFACE*, LPBOOL) PURE;
    STDMETHOD(Clear) (THIS_ DWORD, LPD3DRECT, DWORD) PURE;
    STDMETHOD(AddLight) (THIS_ LPDIRECT3DLIGHT) PURE;
    STDMETHOD(DeleteLight) (THIS_ LPDIRECT3DLIGHT) PURE;
    STDMETHOD(NextLight) (THIS_ LPDIRECT3DLIGHT, LPDIRECT3DLIGHT*, DWORD) PURE;
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IDirect3DViewport_QueryInterface(p, a, b)          (p)->lpVtbl->QueryInterface(p, a, b)
#define IDirect3DViewport_AddRef(p)                        (p)->lpVtbl->AddRef(p)
#define IDirect3DViewport_Release(p)                       (p)->lpVtbl->Release(p)
#define IDirect3DViewport_Initialize(p, a)                 (p)->lpVtbl->Initialize(p, a)
#define IDirect3DViewport_GetViewport(p, a)                (p)->lpVtbl->GetViewport(p, a)
#define IDirect3DViewport_SetViewport(p, a)                (p)->lpVtbl->SetViewport(p, a)
#define IDirect3DViewport_TransformVertices(p, a, b, c, d) (p)->lpVtbl->TransformVertices(p, a, b, c, d)
#define IDirect3DViewport_LightElements(p, a, b)           (p)->lpVtbl->LightElements(p, a, b)
#define IDirect3DViewport_SetBackground(p, a)              (p)->lpVtbl->SetBackground(p, a)
#define IDirect3DViewport_GetBackground(p, a, b)           (p)->lpVtbl->GetBackground(p, a, b)
#define IDirect3DViewport_SetBackgroundDepth(p, a)         (p)->lpVtbl->SetBackgroundDepth(p, a)
#define IDirect3DViewport_GetBackgroundDepth(p, a, b)      (p)->lpVtbl->GetBackgroundDepth(p, a, b)
#define IDirect3DViewport_Clear(p, a, b, c)                (p)->lpVtbl->Clear(p, a, b, c)
#define IDirect3DViewport_AddLight(p, a)                   (p)->lpVtbl->AddLight(p, a)
#define IDirect3DViewport_DeleteLight(p, a)                (p)->lpVtbl->DeleteLight(p, a)
#define IDirect3DViewport_NextLight(p, a, b, c)            (p)->lpVtbl->NextLight(p, a, b, c)
#else
#define IDirect3DViewport_QueryInterface(p, a, b)          (p)->QueryInterface(a, b)
#define IDirect3DViewport_AddRef(p)                        (p)->AddRef()
#define IDirect3DViewport_Release(p)                       (p)->Release()
#define IDirect3DViewport_Initialize(p, a)                 (p)->Initialize(a)
#define IDirect3DViewport_GetViewport(p, a)                (p)->GetViewport(a)
#define IDirect3DViewport_SetViewport(p, a)                (p)->SetViewport(a)
#define IDirect3DViewport_TransformVertices(p, a, b, c, d) (p)->TransformVertices(a, b, c, d)
#define IDirect3DViewport_LightElements(p, a, b)           (p)->LightElements(a, b)
#define IDirect3DViewport_SetBackground(p, a)              (p)->SetBackground(a)
#define IDirect3DViewport_GetBackground(p, a, b)           (p)->GetBackground(a, b)
#define IDirect3DViewport_SetBackgroundDepth(p, a)         (p)->SetBackgroundDepth(a)
#define IDirect3DViewport_GetBackgroundDepth(p, a, b)      (p)->GetBackgroundDepth(a, b)
#define IDirect3DViewport_Clear(p, a, b, c)                (p)->Clear(a, b, c)
#define IDirect3DViewport_AddLight(p, a)                   (p)->AddLight(a)
#define IDirect3DViewport_DeleteLight(p, a)                (p)->DeleteLight(a)
#define IDirect3DViewport_NextLight(p, a, b, c)            (p)->NextLight(a, b, c)
#endif

/*
 * IDirect3DViewport2
 */
#undef INTERFACE
#define INTERFACE IDirect3DViewport2
DECLARE_INTERFACE_(IDirect3DViewport2, IDirect3DViewport)
{
    /*** IUnknown methods ***/
    STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID* ppvObj) PURE;
    STDMETHOD_(ULONG, AddRef) (THIS) PURE;
    STDMETHOD_(ULONG, Release) (THIS) PURE;
    /*** IDirect3DViewport methods ***/
    STDMETHOD(Initialize) (THIS_ LPDIRECT3D) PURE;
    STDMETHOD(GetViewport) (THIS_ LPD3DVIEWPORT) PURE;
    STDMETHOD(SetViewport) (THIS_ LPD3DVIEWPORT) PURE;
    STDMETHOD(TransformVertices) (THIS_ DWORD, LPD3DTRANSFORMDATA, DWORD, LPDWORD) PURE;
    STDMETHOD(LightElements) (THIS_ DWORD, LPD3DLIGHTDATA) PURE;
    STDMETHOD(SetBackground) (THIS_ D3DMATERIALHANDLE) PURE;
    STDMETHOD(GetBackground) (THIS_ LPD3DMATERIALHANDLE, LPBOOL) PURE;
    STDMETHOD(SetBackgroundDepth) (THIS_ LPDIRECTDRAWSURFACE) PURE;
    STDMETHOD(GetBackgroundDepth) (THIS_ LPDIRECTDRAWSURFACE*, LPBOOL) PURE;
    STDMETHOD(Clear) (THIS_ DWORD, LPD3DRECT, DWORD) PURE;
    STDMETHOD(AddLight) (THIS_ LPDIRECT3DLIGHT) PURE;
    STDMETHOD(DeleteLight) (THIS_ LPDIRECT3DLIGHT) PURE;
    STDMETHOD(NextLight) (THIS_ LPDIRECT3DLIGHT, LPDIRECT3DLIGHT*, DWORD) PURE;
    /*** IDirect3DViewport2 methods ***/
    STDMETHOD(GetViewport2) (THIS_ LPD3DVIEWPORT2) PURE;
    STDMETHOD(SetViewport2) (THIS_ LPD3DVIEWPORT2) PURE;
};

#if !defined(__cplusplus) || defined(CINTERFACE)
#define IDirect3DViewport2_QueryInterface(p, a, b)          (p)->lpVtbl->QueryInterface(p, a, b)
#define IDirect3DViewport2_AddRef(p)                        (p)->lpVtbl->AddRef(p)
#define IDirect3DViewport2_Release(p)                       (p)->lpVtbl->Release(p)
#define IDirect3DViewport2_Initialize(p, a)                 (p)->lpVtbl->Initialize(p, a)
#define IDirect3DViewport2_GetViewport(p, a)                (p)->lpVtbl->GetViewport(p, a)
#define IDirect3DViewport2_SetViewport(p, a)                (p)->lpVtbl->SetViewport(p, a)
#define IDirect3DViewport2_TransformVertices(p, a, b, c, d) (p)->lpVtbl->TransformVertices(p, a, b, c, d)
#define IDirect3DViewport2_LightElements(p, a, b)           (p)->lpVtbl->LightElements(p, a, b)
#define IDirect3DViewport2_SetBackground(p, a)              (p)->lpVtbl->SetBackground(p, a)
#define IDirect3DViewport2_GetBackground(p, a, b)           (p)->lpVtbl->GetBackground(p, a, b)
#define IDirect3DViewport2_SetBackgroundDepth(p, a)         (p)->lpVtbl->SetBackgroundDepth(p, a)
#define IDirect3DViewport2_GetBackgroundDepth(p, a, b)      (p)->lpVtbl->GetBackgroundDepth(p, a, b)
#define IDirect3DViewport2_Clear(p, a, b, c)                (p)->lpVtbl->Clear(p, a, b, c)
#define IDirect3DViewport2_AddLight(p, a)                   (p)->lpVtbl->AddLight(p, a)
#define IDirect3DViewport2_DeleteLight(p, a)                (p)->lpVtbl->DeleteLight(p, a)
#define IDirect3DViewport2_NextLight(p, a, b, c)            (p)->lpVtbl->NextLight(p, a, b, c)
#define IDirect3DViewport2_GetViewport2(p, a)                (p)->lpVtbl->GetViewport2(p, a)
#define IDirect3DViewport2_SetViewport2(p, a)                (p)->lpVtbl->SetViewport2(p, a)
#else
#define IDirect3DViewport2_QueryInterface(p, a, b)          (p)->QueryInterface(a, b)
#define IDirect3DViewport2_AddRef(p)                        (p)->AddRef()
#define IDirect3DViewport2_Release(p)                       (p)->Release()
#define IDirect3DViewport2_Initialize(p, a)                 (p)->Initialize(a)
#define IDirect3DViewport2_GetViewport(p, a)                (p)->GetViewport(a)
#define IDirect3DViewport2_SetViewport(p, a)                (p)->SetViewport(a)
#define IDirect3DViewport2_TransformVertices(p, a, b, c, d) (p)->TransformVertices(a, b, c, d)
#define IDirect3DViewport2_LightElements(p, a, b)           (p)->LightElements(a, b)
#define IDirect3DViewport2_SetBackground(p, a)              (p)->SetBackground(a)
#define IDirect3DViewport2_GetBackground(p, a, b)           (p)->GetBackground(a, b)
#define IDirect3DViewport2_SetBackgroundDepth(p, a)         (p)->SetBackgroundDepth(a)
#define IDirect3DViewport2_GetBackgroundDepth(p, a, b)      (p)->GetBackgroundDepth(a, b)
#define IDirect3DViewport2_Clear(p, a, b, c)                (p)->Clear(a, b, c)
#define IDirect3DViewport2_AddLight(p, a)                   (p)->AddLight(a)
#define IDirect3DViewport2_DeleteLight(p, a)                (p)->DeleteLight(a)
#define IDirect3DViewport2_NextLight(p, a, b, c)            (p)->NextLight(a, b, c)
#define IDirect3DViewport2_GetViewport2(p, a)                (p)->GetViewport2(a)
#define IDirect3DViewport2_SetViewport2(p, a)                (p)->SetViewport2(a)
#endif


/****************************************************************************
 *
 * Flags for IDirect3DDevice::NextViewport
 *
 ****************************************************************************/

/*
 * Return the next viewport
 */
#define D3DNEXT_NEXT	0x00000001l

/*
 * Return the first viewport
 */
#define D3DNEXT_HEAD	0x00000002l

/*
 * Return the last viewport
 */
#define D3DNEXT_TAIL	0x00000004l


/****************************************************************************
 *
 * Flags for DrawPrimitive/DrawIndexedPrimitive
 *   Also valid for Begin/BeginIndexed
 *
 ****************************************************************************/

/*
 * Wait until the device is ready to draw the primitive
 * This will cause DP to not return DDERR_WASSTILLDRAWING
 */
#define D3DDP_WAIT					0x00000001l


/*
 * Hint that the primitives have been clipped by the application.
 */
#define D3DDP_DONOTCLIP				0x00000004l

/*
 * Hint that the extents need not be updated.
 */
#define D3DDP_DONOTUPDATEEXTENTS	0x00000008l

/*
 * Direct3D Errors
 * DirectDraw error codes are used when errors not specified here.
 */
#define D3D_OK				DD_OK
#define D3DERR_BADMAJORVERSION		MAKE_DDHRESULT(700)
#define D3DERR_BADMINORVERSION		MAKE_DDHRESULT(701)

/*
 * An invalid device was requested by the application.
 */
#define D3DERR_INVALID_DEVICE   MAKE_DDHRESULT(705)
#define D3DERR_INITFAILED       MAKE_DDHRESULT(706)

/*
 * SetRenderTarget attempted on a device that was
 * QI'd off the render target.
 */
#define D3DERR_DEVICEAGGREGATED MAKE_DDHRESULT(707)

#define D3DERR_EXECUTE_CREATE_FAILED	MAKE_DDHRESULT(710)
#define D3DERR_EXECUTE_DESTROY_FAILED	MAKE_DDHRESULT(711)
#define D3DERR_EXECUTE_LOCK_FAILED	MAKE_DDHRESULT(712)
#define D3DERR_EXECUTE_UNLOCK_FAILED	MAKE_DDHRESULT(713)
#define D3DERR_EXECUTE_LOCKED		MAKE_DDHRESULT(714)
#define D3DERR_EXECUTE_NOT_LOCKED	MAKE_DDHRESULT(715)

#define D3DERR_EXECUTE_FAILED		MAKE_DDHRESULT(716)
#define D3DERR_EXECUTE_CLIPPED_FAILED	MAKE_DDHRESULT(717)

#define D3DERR_TEXTURE_NO_SUPPORT	MAKE_DDHRESULT(720)
#define D3DERR_TEXTURE_CREATE_FAILED	MAKE_DDHRESULT(721)
#define D3DERR_TEXTURE_DESTROY_FAILED	MAKE_DDHRESULT(722)
#define D3DERR_TEXTURE_LOCK_FAILED	MAKE_DDHRESULT(723)
#define D3DERR_TEXTURE_UNLOCK_FAILED	MAKE_DDHRESULT(724)
#define D3DERR_TEXTURE_LOAD_FAILED	MAKE_DDHRESULT(725)
#define D3DERR_TEXTURE_SWAP_FAILED	MAKE_DDHRESULT(726)
#define D3DERR_TEXTURE_LOCKED		MAKE_DDHRESULT(727)
#define D3DERR_TEXTURE_NOT_LOCKED	MAKE_DDHRESULT(728)
#define D3DERR_TEXTURE_GETSURF_FAILED	MAKE_DDHRESULT(729)

#define D3DERR_MATRIX_CREATE_FAILED	MAKE_DDHRESULT(730)
#define D3DERR_MATRIX_DESTROY_FAILED	MAKE_DDHRESULT(731)
#define D3DERR_MATRIX_SETDATA_FAILED	MAKE_DDHRESULT(732)
#define D3DERR_MATRIX_GETDATA_FAILED	MAKE_DDHRESULT(733)
#define D3DERR_SETVIEWPORTDATA_FAILED	MAKE_DDHRESULT(734)

#define D3DERR_INVALIDCURRENTVIEWPORT   MAKE_DDHRESULT(735)
#define D3DERR_INVALIDPRIMITIVETYPE     MAKE_DDHRESULT(736)
#define D3DERR_INVALIDVERTEXTYPE        MAKE_DDHRESULT(737)
#define D3DERR_TEXTURE_BADSIZE          MAKE_DDHRESULT(738)
#define D3DERR_INVALIDRAMPTEXTURE		MAKE_DDHRESULT(739)

#define D3DERR_MATERIAL_CREATE_FAILED	MAKE_DDHRESULT(740)
#define D3DERR_MATERIAL_DESTROY_FAILED	MAKE_DDHRESULT(741)
#define D3DERR_MATERIAL_SETDATA_FAILED	MAKE_DDHRESULT(742)
#define D3DERR_MATERIAL_GETDATA_FAILED	MAKE_DDHRESULT(743)
#define D3DERR_INVALIDPALETTE	        MAKE_DDHRESULT(744)

#define D3DERR_ZBUFF_NEEDS_SYSTEMMEMORY MAKE_DDHRESULT(745)
#define D3DERR_ZBUFF_NEEDS_VIDEOMEMORY  MAKE_DDHRESULT(746)
#define D3DERR_SURFACENOTINVIDMEM       MAKE_DDHRESULT(747)

#define D3DERR_LIGHT_SET_FAILED		MAKE_DDHRESULT(750)
#define D3DERR_LIGHTHASVIEWPORT		MAKE_DDHRESULT(751)
#define D3DERR_LIGHTNOTINTHISVIEWPORT           MAKE_DDHRESULT(752)

#define D3DERR_SCENE_IN_SCENE		MAKE_DDHRESULT(760)
#define D3DERR_SCENE_NOT_IN_SCENE	MAKE_DDHRESULT(761)
#define D3DERR_SCENE_BEGIN_FAILED	MAKE_DDHRESULT(762)
#define D3DERR_SCENE_END_FAILED		MAKE_DDHRESULT(763)

#define D3DERR_INBEGIN                  MAKE_DDHRESULT(770)
#define D3DERR_NOTINBEGIN               MAKE_DDHRESULT(771)
#define D3DERR_NOVIEWPORTS              MAKE_DDHRESULT(772)
#define D3DERR_VIEWPORTDATANOTSET       MAKE_DDHRESULT(773)
#define D3DERR_VIEWPORTHASNODEVICE      MAKE_DDHRESULT(774)
#define D3DERR_NOCURRENTVIEWPORT		MAKE_DDHRESULT(775)

#ifdef __cplusplus
};
#endif

#endif /* _D3D_H_ */
