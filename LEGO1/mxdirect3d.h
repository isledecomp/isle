#ifndef MXDIRECT3D_H
#define MXDIRECT3D_H

#include "mxdirectdraw.h"
#include "mxtypes.h"
#include "decomp.h"

#include <d3d.h>

// SIZE 0xe4
class MxDeviceModeFinder
{
public:
  MxDeviceModeFinder();
  ~MxDeviceModeFinder();

  undefined4 m_unknown[56];
  MxDirectDraw::DeviceModesInfo *m_deviceInfo; // +0xe0
};

// SIZE 0x198
class MxDeviceEnumerate
{
public:
  MxDeviceEnumerate();
  MxResult _DoEnumerate();

  undefined4 m_unk000;
  undefined4 m_unk004;
  undefined4 m_unk008;
  undefined4 m_unk00c;
  BOOL m_unk010_flag; // +0x20

  undefined4 m_unknown[97];
};

// VTABLE 0x100db800
// SIZE 0x894
class MxDirect3D : public MxDirectDraw
{
public:
  MxDirect3D();

  void Clear();
  inline MxDeviceModeFinder *GetDeviceModeFinder() { return this->m_pDeviceModeFinder; };

  virtual ~MxDirect3D();
  virtual BOOL Create(
    HWND hWnd,
    BOOL fullscreen_1,
    BOOL surface_fullscreen,
    BOOL onlySystemMemory,
    int width,
    int height,
    int bpp,
    const PALETTEENTRY* pPaletteEntries,
    int paletteEntryCount);
  virtual void Destroy();

  BOOL CreateIDirect3D();
  BOOL D3DSetMode();
  BOOL FUN_1009c070();
  MxResult _DoEnumerate();

  static void BuildErrorString(const char *, char *);
  static char *D3DErrorToString(HRESULT p_error);

private:
  MxDeviceModeFinder *m_pDeviceModeFinder; // +0x880
  IDirect3D *m_pDirect3d; // +0x884
  IDirect3DDevice *m_pDirect3dDevice;
  undefined4 m_unk88c;
  undefined4 m_unk890;
};

BOOL FAR PASCAL EnumerateCallback(GUID FAR *, LPSTR, LPSTR, LPVOID);

#endif // MXDIRECT3D_H