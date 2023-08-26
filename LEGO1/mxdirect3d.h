#ifndef MXDIRECT3D_H
#define MXDIRECT3D_H

#include "mxdirectdraw.h"
#include "decomp.h"

#include <d3d.h>

class MxDeviceModeFinder;

// SIZE 0x894
class MxDirect3D : public MxDirectDraw
{
public:
  MxDirect3D();

  inline MxDeviceModeFinder *GetDeviceModeFinder() { return this->m_pDeviceModeFinder; };

private:
  MxDeviceModeFinder *m_pDeviceModeFinder;
  IDirect3D *m_pDirect3d;
  IDirect3DDevice *m_pDirect3dDevice;
  undefined4 m_unk88c;
  undefined4 m_unk890;
};

#endif // MXDIRECT3D_H