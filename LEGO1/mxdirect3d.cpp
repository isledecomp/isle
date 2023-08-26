#include "mxdirect3d.h"

DECOMP_SIZE_ASSERT(MxDirect3D, 0x894);

// OFFSET: LEGO1 0x1009b0a0
MxDirect3D::MxDirect3D()
{
  this->m_pDirect3d = NULL;
  this->m_pDirect3dDevice = NULL;
  this->m_unk88c = NULL;
  this->m_pDeviceModeFinder = NULL;
}

// OFFSET: LEGO1 0x1009b290
void MxDirect3D::Clear()
{
  if(this->m_pDirect3dDevice) {
    this->m_pDirect3dDevice->Release();
    this->m_pDirect3dDevice = NULL;
  }
  if(this->m_pDirect3d) {
    this->m_pDirect3d->Release();
    this->m_pDirect3d = NULL;
  }
  Destroy();
}