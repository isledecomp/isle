
#include "mxdirect3drmdevice.h"

#include "ddraw.h"

// Not sure what the deal is with these small holder structs. They might
// actually be the first part of a larger class because I haven't worked out
// enough code further up the call chain to work my way back to a constructor.
struct D3DHolder
{
  IDirect3D *m_pDirect3D;
  IDirect3DDevice *m_pDirect3DDevice;
};

struct D3DSurfaceHolder
{
  IDirectDraw* m_pDirectDraw;
  int unk;
  IDirectDrawSurface* m_pDirectDrawSurface;
};

// VTABLE 0x100db948
class IMxDirect3DRM : public IMxDirect3DRMObject
{
public:
  virtual ~IMxDirect3DRM() {}

  virtual IUnknown **GetHandle() = 0;
  virtual MxDirect3DRMDevice *CreateDeviceFromD3D(D3DHolder *p_holder) = 0;
};

// VTABLE 0x100db910
class MxDirect3DRM : public IMxDirect3DRM
{
public:
  inline MxDirect3DRM();
  virtual ~MxDirect3DRM();

  static MxDirect3DRM *Create();

  virtual IUnknown **GetHandle();
  virtual MxDirect3DRMDevice *CreateDeviceFromD3D(D3DHolder *p_holder);
  virtual MxDirect3DRMDevice *CreateDeviceFromSurface(D3DSurfaceHolder *p_holder);

private:
  IDirect3DRM *m_pD3DRM;
};