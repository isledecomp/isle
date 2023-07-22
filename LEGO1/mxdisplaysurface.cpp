#include "mxdisplaysurface.h"

DECOMP_SIZE_ASSERT(MxDisplaySurface, 0xac);

// OFFSET: LEGO1 0x100ba500
MxDisplaySurface::MxDisplaySurface()
{
  this->Reset();
}

// OFFSET: LEGO1 0x100ba5a0
MxDisplaySurface::~MxDisplaySurface()
{
  this->Clear();
}

// OFFSET: LEGO1 0x100ba610
void MxDisplaySurface::Reset()
{
  this->m_ddSurface1 = NULL;
  this->m_ddSurface2 = NULL;
  this->m_ddClipper = NULL;
  this->m_16bitPal = NULL;
  this->m_initialized = FALSE;
  memset(&this->m_surfaceDesc, 0, sizeof(this->m_surfaceDesc));
}

// OFFSET: LEGO1 0x100ba790
MxResult MxDisplaySurface::Init(MxVideoParam &p_videoParam, LPDIRECTDRAWSURFACE p_ddSurface1, LPDIRECTDRAWSURFACE p_ddSurface2, LPDIRECTDRAWCLIPPER p_ddClipper)
{
  MxResult result = SUCCESS;

  this->m_videoParam = p_videoParam;
  this->m_ddSurface1 = p_ddSurface1;
  this->m_ddSurface2 = p_ddSurface2;
  this->m_ddClipper = p_ddClipper;
  this->m_initialized = FALSE;

  memset(&this->m_surfaceDesc, 0, sizeof(this->m_surfaceDesc));
  this->m_surfaceDesc.dwSize = sizeof(this->m_surfaceDesc);

  if (this->m_ddSurface2->GetSurfaceDesc(&this->m_surfaceDesc))
    result = FAILURE;

  return result;
}

// OFFSET: LEGO1 0x100ba7f0 STUB
MxResult MxDisplaySurface::Create(MxVideoParam *p_videoParam)
{
  return 0;
}

// OFFSET: LEGO1 0x100baa90
void MxDisplaySurface::Clear()
{
  if (this->m_initialized) {
    if (this->m_ddSurface2)
      this->m_ddSurface2->Release();

    if (this->m_ddSurface1)
      this->m_ddSurface1->Release();

    if (this->m_ddClipper)
      this->m_ddClipper->Release();
  }

  if (this->m_16bitPal)
    delete this->m_16bitPal;

  this->Reset();
}

// OFFSET: LEGO1 0x100baae0 STUB
void MxDisplaySurface::SetPalette(MxPalette *p_palette)
{

}

// OFFSET: LEGO1 0x100bc200 STUB
void MxDisplaySurface::vtable24(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4)
{

}

// OFFSET: LEGO1 0x100bacc0 STUB
MxBool MxDisplaySurface::vtable28(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4)
{
  return 0;
}

// OFFSET: LEGO1 0x100bc630 STUB
MxBool MxDisplaySurface::vtable2c(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, MxBool)
{
  return 0;
}

// OFFSET: LEGO1 0x100bb1d0 STUB
MxBool MxDisplaySurface::vtable30(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, MxBool)
{
  return 0;
}

// OFFSET: LEGO1 0x100bb850 STUB
undefined4 MxDisplaySurface::vtable34(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4)
{
  return 0;
}

// OFFSET: LEGO1 0x100bba50 STUB
void MxDisplaySurface::Display(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4)
{

}

// OFFSET: LEGO1 0x100bbc10
void MxDisplaySurface::GetDC(HDC *p_hdc)
{
  if (this->m_ddSurface2 && !this->m_ddSurface2->GetDC(p_hdc))
    return;
 
  *p_hdc = NULL;
}

// OFFSET: LEGO1 0x100bbc40
void MxDisplaySurface::ReleaseDC(HDC p_hdc)
{
  if (this->m_ddSurface2 && p_hdc)
    this->m_ddSurface2->ReleaseDC(p_hdc);
}

// OFFSET: LEGO1 0x100bbc60 STUB
undefined4 MxDisplaySurface::vtable44(undefined4, undefined4*, undefined4, undefined4)
{
  return 0;
}
