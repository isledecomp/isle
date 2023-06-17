#pragma comment(lib, "ddraw")

#include "mxdirectdraw.h"

BOOL g_paletteIndexed8 = 0;
BOOL DAT_10100c70 = 0;

HRESULT MxDirectDraw::SetEntries()
{
  HRESULT ret;

  if (m_paletteIndexed8) {
    if (m_ddpal) {
      ret = m_ddpal->SetEntries(0, 0, 256, m_pal1);
      if (ret != DD_OK) {
        FUN_1009e830("SetEntries failed", ret);
        return 0;
      }
    }
  }

  return 1;
}

HRESULT MxDirectDraw::FlipToGDISurface()
{
  HRESULT ret;

  if (m_ddraw) {
    ret = m_ddraw->FlipToGDISurface();
    if (ret != DD_OK) {
      FUN_1009e830("FlipToGDISurface failed", ret);
    }
    return !ret;
  }

  return 1;
}

void MxDirectDraw::FUN_1009e830(char *error_msg, HRESULT ret)
{
  if (!DAT_10100c70) {
    DAT_10100c70 = 1;
    vtable08();
    if (m_unk85c) {
      m_unk85c(error_msg, ret, m_unk864);
    }
  }

  DAT_10100c70 = 0;
}

int MxDirectDraw::GetPrimaryBitDepth()
{
  DWORD dwRGBBitCount;
  LPDIRECTDRAW pDDraw;
  DDSURFACEDESC ddsd;

  HRESULT result = DirectDrawCreate(NULL, &pDDraw, NULL);
  dwRGBBitCount = 8;
  if (!result)
  {
    memset(&ddsd, 0, sizeof(ddsd));
    ddsd.dwSize = sizeof(ddsd);

    pDDraw->GetDisplayMode(&ddsd);
    dwRGBBitCount = ddsd.ddpfPixelFormat.dwRGBBitCount;
    g_paletteIndexed8 = (ddsd.ddpfPixelFormat.dwFlags & DDPF_PALETTEINDEXED8) != 0;
    pDDraw->Release();
  }

  return dwRGBBitCount;
}

int MxDirectDraw::Pause(int param_1)
{
  if (param_1) {
    m_unk86c++;

    if (m_unk86c > 1) {
      return 1;
    }

    if (!SetEntries()) {
      return 0;
    }

    if (m_fullScreen) {
      if (!FlipToGDISurface()) {
        return 0;
      }

      DrawMenuBar(hWindow);
      RedrawWindow(hWindow, NULL, NULL, RDW_FRAME);
    }

    return 1;
  } else {
    m_unk86c--;
    if (m_unk86c > 0) {
      return 1;
    } else if (m_unk86c < 0) {
      m_unk86c = 0;
    }
    FUN_1009e750();
  }
  return 0;
}


HRESULT MxDirectDraw::FUN_1009e750()
{
  HRESULT ret;

  if (m_fullScreen && m_paletteIndexed8) {
    if (m_ddpal) {
      ret = m_ddpal->SetEntries(0, 0, 256, m_pal0);
      if (ret != DD_OK) {
        FUN_1009e830("SetEntries failed", ret);
        return 0;
      }
    }
  }

  return 1;
}
