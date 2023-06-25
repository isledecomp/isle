
#include "mxdirectdraw.h"

// OFFSET: LEGO1 10100C68
extern BOOL g_is_PALETTEINDEXED8 = 0;

// OFFSET: LEGO1 0x1009DA20
void EnableResizing(HWND hwnd, BOOL flag)
{
  static DWORD dwStyle;

  if (!flag)
  {
    dwStyle = GetWindowLong(hwnd, GWL_STYLE);
    if (dwStyle & WS_THICKFRAME)
    {
      SetWindowLong(hwnd, GWL_STYLE, GetWindowLong(hwnd, GWL_STYLE) ^ WS_THICKFRAME);
    }
  }
  else
  {
    SetWindowLong(hwnd, GWL_STYLE, dwStyle);
  }
}

// OFFSET: LEGO1 0x1009D490
MxDirectDraw::MxDirectDraw()
{
  m_pFrontBuffer = NULL;
  m_pBackBuffer = NULL;
  m_pZBuffer = NULL;
  m_pClipper = NULL;
  m_pPalette = NULL;
  m_pDirectDraw = NULL;
  m_pText1Surface = NULL;
  m_pText2Surface = NULL;
  m_hWndMain = NULL;
  m_bIgnoreWM_SIZE = FALSE;
  m_bPrimaryPalettized = FALSE;
  m_bOnlySystemMemory = FALSE;
  m_bFullScreen = FALSE;
  m_bOnlySoftRender = FALSE;
  m_pauseCount = 0;
  m_pErrorHandler = NULL;
  m_pFatalErrorHandler = NULL;
  m_pErrorHandlerArg = NULL;
  m_pFatalErrorHandlerArg = NULL;
  m_pCurrentDeviceModesList = NULL;
  m_bIsOnPrimaryDevice = TRUE;
  m_hFont = NULL;
}

// OFFSET: LEGO1 0x1009D530
MxDirectDraw::~MxDirectDraw()
{
  Destroy();

  if (m_pCurrentDeviceModesList != NULL)
  {
    delete m_pCurrentDeviceModesList;
    m_pCurrentDeviceModesList = NULL;
  }
}

// OFFSET: LEGO1 0x1009D5E0
BOOL MxDirectDraw::Create(
  HWND hWnd,
  BOOL fullscreen_1,
  BOOL surface_fullscreen,
  BOOL onlySystemMemory,
  int width,
  int height,
  int bpp,
  const PALETTEENTRY* pPaletteEntries,
  int paletteEntryCount)
{
  m_hWndMain = hWnd;

  CacheOriginalPaletteEntries();

  if (!RecreateDirectDraw(&m_pCurrentDeviceModesList->p_guid))
  {
    return FALSE;
  }

  m_bFlipSurfaces = surface_fullscreen;
  BOOL fullscreen = 1;
  m_bOnlySystemMemory = onlySystemMemory;
  m_bIsOnPrimaryDevice = (m_pCurrentDeviceModesList->p_guid == 0);
  if (m_bIsOnPrimaryDevice)
  {
    fullscreen = fullscreen_1;
  }

  if (!SetPaletteEntries(pPaletteEntries, paletteEntryCount, fullscreen))
  {
    return FALSE;
  }

  if (!DDInit(fullscreen))
  {
    return FALSE;
  }

  if (!DDSetMode(width, height, bpp))
  {
    return FALSE;
  }

  return TRUE;
}

// OFFSET: LEGO1 0x1009D800
void MxDirectDraw::Destroy()
{
  DestroyButNotDirectDraw();

  unk2();

  if (m_pDirectDraw != NULL)
  {
    m_pDirectDraw->Release();
    m_pDirectDraw = NULL;
  }

  m_bIsOnPrimaryDevice = TRUE;

  if (m_pCurrentDeviceModesList != NULL)
  {
    delete m_pCurrentDeviceModesList;
    m_pCurrentDeviceModesList = NULL;
  }
}

// OFFSET: LEGO1 0x1009D860
void MxDirectDraw::DestroyButNotDirectDraw()
{
  RestoreOriginalPaletteEntries();
  if (m_bFullScreen)
  {
    if (m_pDirectDraw != NULL)
    {
      m_bIgnoreWM_SIZE = TRUE;
      m_pDirectDraw->RestoreDisplayMode();
      m_bIgnoreWM_SIZE = FALSE;
    }
  }

  if (m_pPalette)
  {
    m_pPalette->Release();
    m_pPalette = NULL;
  }

  if (m_pClipper)
  {
    m_pClipper->Release();
    m_pClipper = NULL;
  }

  if (m_pText1Surface)
  {
    m_pText1Surface->Release();
    m_pText1Surface = NULL;
  }

  if (m_pText2Surface)
  {
    m_pText2Surface->Release();
    m_pText2Surface = NULL;
  }

  if (m_pZBuffer)
  {
    m_pZBuffer->Release();
    m_pZBuffer = NULL;
  }

  if (m_pBackBuffer)
  {
    m_pBackBuffer->Release();
    m_pBackBuffer = NULL;
  }

  if (m_pFrontBuffer)
  {
    m_pFrontBuffer->Release();
    m_pFrontBuffer = NULL;
  }
}

// OFFSET: LEGO1 0x1009E880
const char* MxDirectDraw::ErrorToString(HRESULT error)
{
  //TODO
}


// OFFSET: LEGO1 0x1009D6C0
BOOL MxDirectDraw::CacheOriginalPaletteEntries()
{
  HDC DC;

  if (g_is_PALETTEINDEXED8)
  {
    DC = GetDC(0);
    GetSystemPaletteEntries(DC, 0, _countof(m_originalPaletteEntries), m_originalPaletteEntries);
    ReleaseDC(0, DC);
  }
  return TRUE;
}


// OFFSET: LEGO1 0x1009DD80
HRESULT MxDirectDraw::CreateDDSurface(
  LPDDSURFACEDESC a2,
  LPDIRECTDRAWSURFACE* a3,
  IUnknown* a4)
{
  return m_pDirectDraw->CreateSurface(a2, a3, a4);
}

// OFFSET: LEGO1 0x1009E250
BOOL MxDirectDraw::CreateTextSurfaces()
{
  HDC DC;
  HRESULT result;
  DDCOLORKEY ddck;
  char dummyinfo[] = "000x000x00 (RAMP) 0000";
  DDSURFACEDESC ddsd;
  char dummyfps[] = "000.00 fps (000.00 fps (000.00 fps) 00000 tps)";

  if (m_hFont != NULL)
  {
    DeleteObject(m_hFont);
  }

  m_hFont = CreateFontA(m_currentMode.width <= 600 ? 12 : 24,
    0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
    ANSI_CHARSET,
    OUT_DEFAULT_PRECIS,
    CLIP_DEFAULT_PRECIS,
    DEFAULT_QUALITY,
    VARIABLE_PITCH,
    "Arial");

  DC = GetDC(NULL);
  SelectObject(DC, m_hFont);
  GetTextExtentPointA(DC, dummyfps, strlen(dummyfps), &m_text1SizeOnSurface);
  GetTextExtentPointA(DC, dummyinfo, strlen(dummyinfo), &m_text2SizeOnSurface);
  ReleaseDC(NULL, DC);

  memset(&ddsd, 0, sizeof(ddsd));
  ddsd.dwSize = sizeof(ddsd);
  ddsd.dwFlags = DDSD_CAPS | DDSD_HEIGHT | DDSD_WIDTH;
  ddsd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN;
  if (m_bOnlySystemMemory)
    ddsd.ddsCaps.dwCaps = DDSCAPS_SYSTEMMEMORY | DDSCAPS_OFFSCREENPLAIN;
  ddsd.dwHeight = m_text1SizeOnSurface.cy;
  ddsd.dwWidth = m_text1SizeOnSurface.cx;

  result = CreateDDSurface(&ddsd, &m_pText1Surface, 0);
  if (result != DD_OK)
  {
    Error("CreateSurface for text surface 1 failed", result);
    return FALSE;
  }

  memset(&ddck, 0, sizeof(ddck));
  m_pText1Surface->SetColorKey(DDCKEY_SRCBLT, &ddck);
  if (!TextToTextSurface1(dummyfps))
  {
    return FALSE;
  }

  memset(&ddsd, 0, sizeof(ddsd));
  ddsd.dwSize = sizeof(ddsd);
  ddsd.dwFlags = DDSD_CAPS | DDSD_HEIGHT | DDSD_WIDTH;
  ddsd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN;
  if (m_bOnlySystemMemory)
    ddsd.ddsCaps.dwCaps = DDSCAPS_SYSTEMMEMORY | DDSCAPS_OFFSCREENPLAIN;
  ddsd.dwHeight = m_text2SizeOnSurface.cy;
  ddsd.dwWidth = m_text2SizeOnSurface.cx;

  result = CreateDDSurface(&ddsd, &m_pText2Surface, 0);
  if (result != DD_OK)
  {
    Error("CreateSurface for text surface 2 failed", result);
    return FALSE;
  }

  memset(&ddck, 0, sizeof(ddck));
  m_pText2Surface->SetColorKey(DDCKEY_SRCBLT, &ddck);
  if (!TextToTextSurface2(dummyfps))
  {
    return FALSE;
  }

  return TRUE;
}

// OFFSET: LEGO1 0x1009E5E0
BOOL MxDirectDraw::CreateZBuffer(DWORD memorytype, DWORD depth)
{
  HRESULT result; // eax
  LPDIRECTDRAWSURFACE lpZBuffer; // [esp+8h] [ebp-70h] BYREF
  DDSURFACEDESC ddsd;

  memset(&ddsd, 0, sizeof(ddsd));
  ddsd.dwSize = sizeof(ddsd);
  ddsd.dwHeight = m_currentMode.height;
  ddsd.dwWidth = m_currentMode.width;
  ddsd.dwZBufferBitDepth = depth;
  ddsd.dwFlags = DDSD_WIDTH | DDSD_HEIGHT | DDSD_CAPS | DDSD_ZBUFFERBITDEPTH;
  ddsd.ddsCaps.dwCaps = DDSCAPS_ZBUFFER | memorytype;

  result = CreateDDSurface(&ddsd, &lpZBuffer, 0);
  if (result != DD_OK)
  {
    Error("CreateSurface for fullScreen Z-buffer failed", result);
    return FALSE;
  }

  result = m_pBackBuffer->AddAttachedSurface(lpZBuffer);
  if (result != DD_OK)
  {
    Error("AddAttachedBuffer failed for Z-Buffer", result);
    return FALSE;
  }

  m_pZBuffer = lpZBuffer;
  return TRUE;
}

// OFFSET: LEGO1 0x1009DDF0
BOOL MxDirectDraw::DDCreateSurfaces()
{
  HRESULT result;
  DDSCAPS ddscaps;
  DDSURFACEDESC ddsd;

  if (m_bFlipSurfaces)
  {
    memset(&ddsd, 0, sizeof(ddsd));
    ddsd.dwSize = sizeof(ddsd);
    ddsd.dwFlags = DDSD_CAPS | DDSD_BACKBUFFERCOUNT;
    ddsd.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE | DDSCAPS_FLIP | DDSCAPS_3DDEVICE | DDSCAPS_COMPLEX;
    if (m_bOnlySystemMemory)
    {
      ddsd.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE | DDSCAPS_FLIP | DDSCAPS_3DDEVICE | DDSCAPS_COMPLEX | DDSCAPS_SYSTEMMEMORY;
    }
    ddsd.dwBackBufferCount = 1;
    result = CreateDDSurface(&ddsd, &m_pFrontBuffer, 0);
    if (result != DD_OK)
    {
      Error("CreateSurface for front/back fullScreen buffer failed", result);
      return FALSE;
    }

    ddscaps.dwCaps = DDSCAPS_BACKBUFFER;
    result = m_pFrontBuffer->GetAttachedSurface(&ddscaps, &m_pBackBuffer);
    if (result != DD_OK)
    {
      Error("GetAttachedSurface failed to get back buffer", result);
      return FALSE;
    }
    if (!GetDDSurfaceDesc(&ddsd, m_pBackBuffer))
    {
      return FALSE;
    }
  }
  else
  {
    memset(&ddsd, 0, sizeof(ddsd));
    ddsd.dwSize = sizeof(ddsd);
    ddsd.dwFlags = DDSD_CAPS;
    ddsd.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE;
    result = CreateDDSurface(&ddsd, &m_pFrontBuffer, NULL);
    if (result != DD_OK)
    {
      Error("CreateSurface for window front buffer failed", result);
      return FALSE;
    }
    ddsd.dwHeight = m_currentMode.height;
    ddsd.dwWidth = m_currentMode.width;
    ddsd.dwFlags = DDSD_WIDTH | DDSD_HEIGHT | DDSD_CAPS;
    ddsd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN | DDSCAPS_3DDEVICE;
    if (m_bOnlySystemMemory)
      ddsd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN | DDSCAPS_3DDEVICE | DDSCAPS_SYSTEMMEMORY;
    result = CreateDDSurface(&ddsd, &m_pBackBuffer, NULL);
    if (result != DD_OK)
    {
      Error("CreateSurface for window back buffer failed", result);
      return FALSE;
    }

    if (!GetDDSurfaceDesc(&ddsd, m_pBackBuffer))
    {
      return FALSE;
    }

    result = m_pDirectDraw->CreateClipper(0, &m_pClipper, NULL);
    if (result != DD_OK)
    {
      Error("CreateClipper failed", result);
      return FALSE;
    }
    result = m_pClipper->SetHWnd(0, m_hWndMain);
    if (result != DD_OK)
    {
      Error("Clipper SetHWnd failed", result);
      return FALSE;
    }
    result = m_pFrontBuffer->SetClipper(m_pClipper);
    if (result != DD_OK)
    {
      Error("SetClipper failed", result);
      return FALSE;
    }
  }

  return TRUE;
}

// OFFSET: LEGO1 0x1009D960
BOOL MxDirectDraw::DDInit(BOOL fullscreen)
{
  HRESULT result;

  if (fullscreen)
  {
    m_bIgnoreWM_SIZE = 1;
    result = m_pDirectDraw->SetCooperativeLevel(m_hWndMain, DDSCL_EXCLUSIVE | DDSCL_FULLSCREEN);
    m_bIgnoreWM_SIZE = 0;
  }
  else
  {
    result = m_pDirectDraw->SetCooperativeLevel(m_hWndMain, DDSCL_NORMAL);
  }

  if (result != DD_OK)
  {
    Error("SetCooperativeLevel failed", result);
    return FALSE;
  }

  m_bFullScreen = fullscreen;

  return TRUE;
}

// OFFSET: LEGO1 0x1009DA80
BOOL MxDirectDraw::DDSetMode(int width, int height, int bpp)
{
  int temp_height;
  int temp_width;
  int temp_bpp;
  HRESULT result;

  if (m_bFullScreen)
  {
    LPDIRECTDRAW lpDD;

    EnableResizing(m_hWndMain, FALSE);

    temp_width = width;
    temp_height = height;
    temp_bpp = bpp;
    if (!m_bIsOnPrimaryDevice)
    {
      result = DirectDrawCreate(0, &lpDD, 0);
      if (result == DD_OK)
      {
        result = lpDD->SetCooperativeLevel(m_hWndMain, DDSCL_FULLSCREEN | DDSCL_EXCLUSIVE | DDSCL_ALLOWREBOOT);
        if (result == DD_OK)
        {
          temp_height = height;
          temp_width = width;
          lpDD->SetDisplayMode(width, height, 8);
        }
      }
    }

    if (!IsSupportedMode(temp_width, temp_height, bpp))
    {
      temp_width = m_pCurrentDeviceModesList->m_mode_ARRAY[0].width;
      temp_height = m_pCurrentDeviceModesList->m_mode_ARRAY[0].height;
      temp_bpp = m_pCurrentDeviceModesList->m_mode_ARRAY[0].bitsPerPixel;
    }

    m_bIgnoreWM_SIZE = TRUE;
    result = m_pDirectDraw->SetDisplayMode(temp_width, temp_height, temp_bpp);
    m_bIgnoreWM_SIZE = FALSE;
    if (result != DD_OK)
    {
      Error("SetDisplayMode failed", result);
      return FALSE;
    }
  }
  else
  {
    RECT rc;
    DWORD dwStyle;

    if (!m_bIsOnPrimaryDevice)
    {
      Error("Attempt made enter a windowed mode on a DirectDraw device that is not the primary display", E_FAIL);
      return FALSE;
    }

    m_bIgnoreWM_SIZE = TRUE;
    dwStyle = GetWindowLong(m_hWndMain, GWL_STYLE);
    dwStyle &= ~(WS_POPUP | WS_CAPTION | WS_THICKFRAME | WS_OVERLAPPED);
    dwStyle |= WS_CAPTION | WS_THICKFRAME | WS_OVERLAPPED;
    SetWindowLong(m_hWndMain, GWL_STYLE, dwStyle);

    temp_height = height;
    temp_width = width;

    SetRect(&rc, 0, 0, width - 1, height - 1);
    AdjustWindowRectEx(
      &rc,
      GetWindowLong(m_hWndMain, GWL_STYLE),
      GetMenu(m_hWndMain) != NULL,
      GetWindowLong(m_hWndMain, GWL_EXSTYLE)
    );
    SetWindowPos(m_hWndMain, 0, 0, 0, rc.right - rc.left, rc.bottom - rc.top, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    SetWindowPos(m_hWndMain, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_NOACTIVATE);
    m_bIgnoreWM_SIZE = FALSE;

    temp_bpp = bpp;
  }

  m_currentMode.width = temp_width;
  m_currentMode.height = temp_height;
  m_currentMode.bitsPerPixel = temp_bpp;

  if (!DDCreateSurfaces())
  {
    return FALSE;
  }

  DDSURFACEDESC ddsd;

  unk1();

  if (!GetDDSurfaceDesc(&ddsd, m_pBackBuffer))
  {
    return FALSE;
  }

  if (ddsd.ddpfPixelFormat.dwFlags & DDPF_PALETTEINDEXED8)
  {
    m_bPrimaryPalettized = TRUE;
  }
  else
  {
    m_bPrimaryPalettized = FALSE;
  }

  if (m_bPrimaryPalettized)
  {
    result = m_pDirectDraw->CreatePalette(
      DDPCAPS_8BIT | DDPCAPS_ALLOW256 | DDPCAPS_INITIALIZE, //0x4c
      m_paletteEntries,
      &m_pPalette,
      NULL);
    if (result != DD_OK)
    {
      Error("CreatePalette failed", result);
      return 0;
    }
    result = m_pBackBuffer->SetPalette(m_pPalette); // TODO: add FIX_BUGS define and fix this
    result = m_pFrontBuffer->SetPalette(m_pPalette);
    if (result != DD_OK)
    {
      Error("SetPalette failed", result);
      return FALSE;
    }
  }

  if (m_bFullScreen)
  {
    return TRUE;
  }
  else
  {
    // create debug text only in windowed mode?
    if (!CreateTextSurfaces())
    {
      return FALSE;
    }
    else
    {
      return TRUE;
    }
  }
}

// OFFSET: LEGO1 0x1009E830
void MxDirectDraw::Error(const char* message, int error)
{
  // OFFSET: LEGO1 0x10100C70
  static BOOL isInsideError = FALSE;
  if (!isInsideError)
  {
    isInsideError = TRUE;
    Destroy();
    if (m_pErrorHandler)
    {
      m_pErrorHandler(message, error, m_pErrorHandlerArg);
    }
    isInsideError = FALSE;
  }
}

// OFFSET: LEGO1 0x1009DDA0
BOOL MxDirectDraw::GetDDSurfaceDesc(LPDDSURFACEDESC lpDDSurfDesc, LPDIRECTDRAWSURFACE lpDDSurf)
{
  HRESULT result;

  memset(lpDDSurfDesc, 0, sizeof(*lpDDSurfDesc));
  lpDDSurfDesc->dwSize = sizeof(*lpDDSurfDesc);
  result = lpDDSurf->GetSurfaceDesc(lpDDSurfDesc);
  if (result != DD_OK)
  {
    Error("Error getting a surface description", result);
  }

  return (result == DD_OK);
}

// OFFSET: LEGO1 0x1009D9D0
BOOL MxDirectDraw::IsSupportedMode(int width, int height, int bpp)
{
  int i;
  Mode mode = { width, height, bpp };

  if (m_pCurrentDeviceModesList->count <= 0)
  {
    return FALSE;
  }

  // TODO: find way to mach original
  for (i = 0; i < m_pCurrentDeviceModesList->count; i++)
  {
    if (m_pCurrentDeviceModesList->m_mode_ARRAY[i] == mode)
    {
      return TRUE;
    }
  }

  return FALSE;
}

// OFFSET: LEGO1 0x1009D690
BOOL MxDirectDraw::RecreateDirectDraw(GUID** ppGUID)
{
  if (m_pDirectDraw)
  {
    m_pDirectDraw->Release();
    m_pDirectDraw = NULL;
  }

  return (DirectDrawCreate(*ppGUID, &m_pDirectDraw, 0) == DD_OK);
}

// OFFSET: LEGO1 0x1009E7A0
BOOL MxDirectDraw::RestoreOriginalPaletteEntries()
{
  HRESULT result;

  if (!m_bPrimaryPalettized)
  {
    return TRUE;
  }

  if (m_pPalette == NULL)
  {
    return TRUE;
  }

  result = m_pPalette->SetEntries(0, 0, 256, m_originalPaletteEntries);
  if (result != DD_OK)
  {
    Error("SetEntries failed", result);
    return FALSE;
  }

  return TRUE;
}

// OFFSET: LEGO1 0x1009E750
BOOL MxDirectDraw::RestorePaletteEntries()
{
  HRESULT result;

  if (!m_bFullScreen)
  {
    return TRUE;
  }

  if (!m_bPrimaryPalettized)
  {
    return TRUE;
  }

  if (m_pPalette == NULL)
  {
    return TRUE;
  }

  result = m_pPalette->SetEntries(0, 0, _countof(m_paletteEntries), m_paletteEntries);
  if (result != DD_OK)
  {
    Error("SetEntries failed", result);
    return FALSE;
  }

  return TRUE;
}

// OFFSET: LEGO1 0x1009E4D0
BOOL MxDirectDraw::RestoreSurfaces()
{
  HRESULT result;

  if (m_pFrontBuffer != NULL)
  {
    if (m_pFrontBuffer->IsLost() == DDERR_SURFACELOST)
    {
      result = m_pFrontBuffer->Restore();
      if (result != DD_OK)
      {
        Error("Restore of front buffer failed", result);
        return FALSE;
      }
    }
  }

  if (m_pBackBuffer != NULL)
  {
    if (m_pBackBuffer->IsLost() == DDERR_SURFACELOST)
    {
      result = m_pBackBuffer->Restore();
      if (result != DD_OK)
      {
        Error("Restore of back buffer failed", result);
        return FALSE;
      }
    }
  }

  if (m_pZBuffer != NULL)
  {
    if (m_pZBuffer->IsLost() == DDERR_SURFACELOST)
    {
      result = m_pZBuffer->Restore();
      if (result != DD_OK)
      {
        Error("Restore of Z-buffer failed", result);
        return FALSE;
      }
    }
  }

  if (m_pText1Surface != NULL)
  {
    if (m_pText1Surface->IsLost() == DDERR_SURFACELOST)
    {
      result = m_pText1Surface->Restore();
      if (result != DD_OK)
      {
        Error("Restore of text surface 1 failed", result);
        return FALSE;
      }
    }
  }

  if (m_pText2Surface != NULL)
  {
    if (m_pText2Surface->IsLost() == DDERR_SURFACELOST)
    {
      result = m_pText2Surface->Restore();
      if (result != DD_OK)
      {
        Error("Restore of text surface 2 failed", result);
        return FALSE;
      }
    }
  }

  return TRUE;
}

// OFFSET: LEGO1 0x1009D700
BOOL MxDirectDraw::SetPaletteEntries(
  const PALETTEENTRY* pPaletteEntries,
  int paletteEntryCount,
  BOOL fullscreen)
{
  HRESULT result;
  HDC hdc;
  int i;

  if (g_is_PALETTEINDEXED8)
  {
    hdc = GetDC(NULL);
    GetSystemPaletteEntries(hdc, 0, _countof(m_paletteEntries), m_paletteEntries);
    ReleaseDC(NULL, hdc);
  }

  for (i = 0; i < 10; i++)
  {
    m_paletteEntries[i].peFlags = 0x80;
  }

  for (i = 10; i < 142; i++)
  {
    m_paletteEntries[i].peFlags = 0x44;
  }

  for (i = 142; i < 246; i++)
  {
    m_paletteEntries[i].peFlags = 0x84;
  }

  for (i = 246; i < 256; i++)
  {
    m_paletteEntries[i].peFlags = 0x80;
  }

  if (paletteEntryCount != 0)
  {
    // actually both of this 'if' statements is not needed(may be it created from for some how)
    if (paletteEntryCount > 10)
    {
      for (i = 10; (i < paletteEntryCount) && (i < 246); i++)
      {
        m_paletteEntries[i].peRed = pPaletteEntries[i].peRed;
        m_paletteEntries[i].peGreen = pPaletteEntries[i].peGreen;
        m_paletteEntries[i].peBlue = pPaletteEntries[i].peBlue;
      }
    }
  }

  if (m_pPalette != NULL)
  {
    result = m_pPalette->SetEntries(0, 0, _countof(m_paletteEntries), m_paletteEntries);
    if (result != DD_OK)
    {
      Error("SetEntries failed", result);
      return FALSE;
    }
  }

  return TRUE;
}

// OFFSET: LEGO1 0x1009E110
BOOL MxDirectDraw::TextToTextSurface(
  const char* text,
  IDirectDrawSurface* pSurface,
  SIZE& textSizeOnSurface)
{
  HRESULT result;
  size_t  textLength;
  HDC hdc;
  struct tagRECT rc;

  if (pSurface == NULL)
  {
    return FALSE;
  }

  result = pSurface->GetDC(&hdc);
  if (result != DD_OK)
  {
    Error("GetDC for text surface failed", result);
    return FALSE;
  }

  textLength = strlen(text) + 1;
  SelectObject(hdc, m_hFont);
  SetTextColor(hdc, RGB(255, 255, 0));
  SetBkColor(hdc, RGB(0, 0, 0));
  SetBkMode(hdc, OPAQUE);
  GetTextExtentPoint32(hdc, text, textLength - 1, &textSizeOnSurface);
  SetRect(&rc, 0, 0, textSizeOnSurface.cx, textSizeOnSurface.cy);
  ExtTextOut(hdc, 0, 0, ETO_OPAQUE, &rc, text, textLength - 1, NULL);
  pSurface->ReleaseDC(hdc);

  return TRUE;
}

// OFFSET: LEGO1 0x1009E210
BOOL MxDirectDraw::TextToTextSurface1(const char* text)
{
  return TextToTextSurface(
    text,
    m_pText1Surface,
    m_text1SizeOnSurface);
}

// OFFSET: LEGO1 0x1009E230
BOOL MxDirectDraw::TextToTextSurface2(const char* text)
{
  return TextToTextSurface(
    text,
    m_pText2Surface,
    m_text2SizeOnSurface);
}

// OFFSET: LEGO1 0x1009E020
void MxDirectDraw::unk1()
{
  HRESULT result;
  byte* line;
  DDSURFACEDESC ddsd;

  for (int i = 0; i < m_bFlipSurfaces ? 2 : 1; i++)
  {
    memset(&ddsd, 0, sizeof(ddsd));
    ddsd.dwSize = sizeof(ddsd);

    result = m_pBackBuffer->Lock(NULL, &ddsd, 1, NULL);
    if (result == DDERR_SURFACELOST)
    {
      m_pBackBuffer->Restore();
      result = m_pBackBuffer->Lock(NULL, &ddsd, 1, NULL);
    }

    if (result != DD_OK)
    {
      // lock failed
      return;
    }

    // clear backBuffer
    line = (byte*)ddsd.lpSurface;
    for (int j = 0; j < ddsd.dwHeight; i++)
    {
      memset(line, 0, ddsd.dwWidth);
      line += ddsd.lPitch;
    }

    m_pBackBuffer->Unlock(ddsd.lpSurface);


    if (m_bFlipSurfaces)
    {
      m_pFrontBuffer->Flip(NULL, DDFLIP_WAIT);
    }
  }
}

// OFFSET: LEGO1 0x1009D920
void MxDirectDraw::unk2()
{
  RestoreOriginalPaletteEntries();
  if (m_pDirectDraw != NULL)
  {
    m_bIgnoreWM_SIZE = TRUE;
    m_pDirectDraw->RestoreDisplayMode();
    m_pDirectDraw->SetCooperativeLevel(NULL, DDSCL_NORMAL);
    m_bIgnoreWM_SIZE = FALSE;
  }
}

