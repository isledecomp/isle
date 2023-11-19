#include "mxdirect3drm.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(IMxDirect3DRM, 0x4);
DECOMP_SIZE_ASSERT(MxDirect3DRM, 0x8);

// OFFSET: LEGO1 0x1010103c
IDirect3DRM* g_pD3DRM = NULL;

// Inlined only
MxDirect3DRM::MxDirect3DRM()
  : m_pD3DRM(NULL)
{
  if (g_pD3DRM == NULL)
  {
    LPDIRECT3DRM handle;
    Direct3DRMCreate(&handle);
    handle->QueryInterface(IID_IDirect3DRM2, (LPVOID*)&g_pD3DRM);
  }
  else
  {
    m_pD3DRM->AddRef();
  }
  m_pD3DRM = g_pD3DRM;
}

// Inlined only
MxDirect3DRM::~MxDirect3DRM()
{
  if (m_pD3DRM)
  {
    if (m_pD3DRM->Release() == 0)
      g_pD3DRM = NULL;
    m_pD3DRM = NULL;
  }
}

// OFFSET: LEGO1 0x100a15e0
MxDirect3DRM* MxDirect3DRM::Create()
{
  // Not a close match. The separate create function implies that
  // the g_pD3DRM handling stuff should be in here rather than in the
  // constructor, but the destructor definitely calls Release() on
  // g_pD3DRM and that implies the opposite.
  return new MxDirect3DRM();
}

// OFFSET: LEGO1 0x100a22b0
IUnknown** MxDirect3DRM::GetHandle()
{
  return (IUnknown**)&m_pD3DRM;
}

// OFFSET: LEGO1 0x100a1894 STUB
MxDirect3DRMDevice* MxDirect3DRM::CreateDeviceFromD3D(D3DHolder* p_holder)
{
  return NULL;
}

// OFFSET: LEGO1 0x100a1900 STUB
MxDirect3DRMDevice* MxDirect3DRM::CreateDeviceFromSurface(D3DSurfaceHolder* p_holder)
{
  return NULL;
}
