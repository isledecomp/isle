
#include "mxdirectdraw.h"

//TODO: make commonn place for defines like that
#ifndef _countof
#define _countof(arr) sizeof(arr) / sizeof(arr[0])
#endif

#ifndef DDSCAPS_3DDEVICE
#define DDSCAPS_3DDEVICE 0x00002000l
#endif

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

// OFFSET: LEGO1 0x1009d570
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
    g_is_PALETTEINDEXED8 = (ddsd.ddpfPixelFormat.dwFlags & DDPF_PALETTEINDEXED8) != 0;
    pDDraw->Release();
}

  return dwRGBBitCount;
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

// OFFSET: LEGO1 0x1009e6a0
int MxDirectDraw::Pause(int p_increment)
{
  if (p_increment)
  {
    m_pauseCount++;

    if (m_pauseCount > 1)
    {
      return TRUE;
    }

    if (!RestoreOriginalPaletteEntries())
    {
      return FALSE;
    }

    if (m_bFullScreen)
    {
      if (!FlipToGDISurface())
      {
        return FALSE;
      }

      DrawMenuBar(m_hWndMain);
      RedrawWindow(m_hWndMain, NULL, NULL, RDW_FRAME);
    }
  }
  else
  {
    m_pauseCount--;
    if (m_pauseCount > 0)
    {
      return TRUE;
    }
    else if (m_pauseCount < 0)
    {
      m_pauseCount = 0;
    }

    if (!RestorePaletteEntries())
    {
      return FALSE;
    }
  }

  return TRUE;
}

// OFFSET: LEGO1 0x1009E880
const char* MxDirectDraw::ErrorToString(HRESULT error)
{
  switch(error) {
    case DD_OK:
      return "No error.";
    case DDERR_ALREADYINITIALIZED:
      return "This object is already initialized.";
    case DDERR_BLTFASTCANTCLIP:
      return "Return if a clipper object is attached to the source surface passed into a BltFast call.";
    case DDERR_CANNOTATTACHSURFACE:
      return "This surface can not be attached to the requested surface.";
    case DDERR_CANNOTDETACHSURFACE:
      return "This surface can not be detached from the requested surface.";
    case DDERR_CANTCREATEDC:
      return "Windows can not create any more DCs.";
    case DDERR_CANTDUPLICATE:
      return "Can't duplicate primary & 3D surfaces, or surfaces that are implicitly created.";
    case DDERR_CLIPPERISUSINGHWND:
      return "An attempt was made to set a cliplist for a clipper object that is already monitoring an hwnd.";
    case DDERR_COLORKEYNOTSET:
      return "No src color key specified for this operation.";
    case DDERR_CURRENTLYNOTAVAIL:
      return "Support is currently not available.";
    case DDERR_DIRECTDRAWALREADYCREATED:
      return "A DirectDraw object representing this driver has already been created for this process.";
    case DDERR_EXCEPTION:
      return "An exception was encountered while performing the requested operation.";
    case DDERR_EXCLUSIVEMODEALREADYSET:
      return "An attempt was made to set the cooperative level when it was already set to exclusive.";
    case DDERR_GENERIC:
      return "Generic failure.";
    case DDERR_HEIGHTALIGN:
      return "Height of rectangle provided is not a multiple of reqd alignment.";
    case DDERR_HWNDALREADYSET:
      return "The CooperativeLevel HWND has already been set. It can not be reset while the process has surfaces or palettes created.";
    case DDERR_HWNDSUBCLASSED:
      return "HWND used by DirectDraw CooperativeLevel has been subclassed, this prevents DirectDraw from restoring state.";
    case DDERR_IMPLICITLYCREATED:
      return "This surface can not be restored because it is an implicitly created surface.";
    case DDERR_INCOMPATIBLEPRIMARY:
      return "Unable to match primary surface creation request with existing primary surface.";
    case DDERR_INVALIDCAPS:
      return "One or more of the caps bits passed to the callback are incorrect.";
    case DDERR_INVALIDCLIPLIST:
      return "DirectDraw does not support the provided cliplist.";
    case DDERR_INVALIDDIRECTDRAWGUID:
      return "The GUID passed to DirectDrawCreate is not a valid DirectDraw driver identifier.";
    case DDERR_INVALIDMODE:
      return "DirectDraw does not support the requested mode.";
    case DDERR_INVALIDOBJECT:
      return "DirectDraw received a pointer that was an invalid DIRECTDRAW object.";
    case DDERR_INVALIDPARAMS:
      return "One or more of the parameters passed to the function are incorrect.";
    case DDERR_INVALIDPIXELFORMAT:
      return "The pixel format was invalid as specified.";
    case DDERR_INVALIDPOSITION:
      return "Returned when the position of the overlay on the destination is no longer legal for that destination.";
    case DDERR_INVALIDRECT:
      return "Rectangle provided was invalid.";
    case DDERR_LOCKEDSURFACES:
      return "Operation could not be carried out because one or more surfaces are locked.";
    case DDERR_NO3D:
      return "There is no 3D present.";
    case DDERR_NOALPHAHW:
      return "Operation could not be carried out because there is no alpha accleration hardware present or available.";
    case DDERR_NOBLTHW:
      return "No blitter hardware present.";
    case DDERR_NOCLIPLIST:
      return "No cliplist available.";
    case DDERR_NOCLIPPERATTACHED:
      return "No clipper object attached to surface object.";
    case DDERR_NOCOLORCONVHW:
      return "Operation could not be carried out because there is no color conversion hardware present or available.";
    case DDERR_NOCOLORKEY:
      return "Surface doesn't currently have a color key";
    case DDERR_NOCOLORKEYHW:
      return "Operation could not be carried out because there is no hardware support of the destination color key.";
    case DDERR_NOCOOPERATIVELEVELSET:
      return "Create function called without DirectDraw object method SetCooperativeLevel being called.";
    case DDERR_NODC:
      return "No DC was ever created for this surface.";
    case DDERR_NODDROPSHW:
      return "No DirectDraw ROP hardware.";
    case DDERR_NODIRECTDRAWHW:
      return "A hardware-only DirectDraw object creation was attempted but the driver did not support any hardware.";
    case DDERR_NOEMULATION:
      return "Software emulation not available.";
    case DDERR_NOEXCLUSIVEMODE:
      return "Operation requires the application to have exclusive mode but the application does not have exclusive mode.";
    case DDERR_NOFLIPHW:
      return "Flipping visible surfaces is not supported.";
    case DDERR_NOGDI:
      return "There is no GDI present.";
    case DDERR_NOHWND:
      return "Clipper notification requires an HWND or no HWND has previously been set as the CooperativeLevel HWND.";
    case DDERR_NOMIRRORHW:
      return "Operation could not be carried out because there is no hardware present or available.";
    case DDERR_NOOVERLAYDEST:
      return "Returned when GetOverlayPosition is called on an overlay that UpdateOverlay has never been called on to establish a destination.";
    case DDERR_NOOVERLAYHW:
      return "Operation could not be carried out because there is no overlay hardware present or available.";
    case DDERR_NOPALETTEATTACHED:
      return "No palette object attached to this surface.";
    case DDERR_NOPALETTEHW:
      return "No hardware support for 16 or 256 color palettes.";
    case DDERR_NORASTEROPHW:
      return "Operation could not be carried out because there is no appropriate raster op hardware present or available.";
    case DDERR_NOROTATIONHW:
      return "Operation could not be carried out because there is no rotation hardware present or available.";
    case DDERR_NOSTRETCHHW:
      return "Operation could not be carried out because there is no hardware support for stretching.";
    case DDERR_NOT4BITCOLOR:
      return "DirectDrawSurface is not in 4 bit color palette and the requested operation requires 4 bit color palette.";
    case DDERR_NOT4BITCOLORINDEX:
      return "DirectDrawSurface is not in 4 bit color index palette and the requested operation requires 4 bit color index palette.";
    case DDERR_NOT8BITCOLOR:
      return "DirectDrawSurface is not in 8 bit color mode and the requested operation requires 8 bit color.";
    case DDERR_NOTAOVERLAYSURFACE:
      return "Returned when an overlay member is called for a non-overlay surface.";
    case DDERR_NOTEXTUREHW:
      return "Operation could not be carried out because there is no texture mapping hardware present or available.";
    case DDERR_NOTFLIPPABLE:
      return "An attempt has been made to flip a surface that is not flippable.";
    case DDERR_NOTFOUND:
      return "Requested item was not found.";
    case DDERR_NOTLOCKED:
      return "Surface was not locked.  An attempt to unlock a surface that was not locked at all, or by this process, has been attempted.";
    case DDERR_NOTPALETTIZED:
      return "The surface being used is not a palette-based surface.";
    case DDERR_NOVSYNCHW:
      return "Operation could not be carried out because there is no hardware support for vertical blank synchronized operations.";
    case DDERR_NOZBUFFERHW:
      return "Operation could not be carried out because there is no hardware support for zbuffer blitting.";
    case DDERR_NOZOVERLAYHW:
      return "Overlay surfaces could not be z layered based on their BltOrder because the hardware does not support z layering of overlays.";
    case DDERR_OUTOFCAPS:
      return "The hardware needed for the requested operation has already been allocated.";
    case DDERR_OUTOFMEMORY:
      return "DirectDraw does not have enough memory to perform the operation.";
    case DDERR_OUTOFVIDEOMEMORY:
      return "DirectDraw does not have enough memory to perform the operation.";
    case DDERR_OVERLAYCANTCLIP:
      return "The hardware does not support clipped overlays.";
    case DDERR_OVERLAYCOLORKEYONLYONEACTIVE:
      return "Can only have ony color key active at one time for overlays.";
    case DDERR_OVERLAYNOTVISIBLE:
      return "Returned when GetOverlayPosition is called on a hidden overlay.";
    case DDERR_PALETTEBUSY:
      return "Access to this palette is being refused because the palette is already locked by another thread.";
    case DDERR_PRIMARYSURFACEALREADYEXISTS:
      return "This process already has created a primary surface.";
    case DDERR_REGIONTOOSMALL:
      return "Region passed to Clipper::GetClipList is too small.";
    case DDERR_SURFACEALREADYATTACHED:
      return "This surface is already attached to the surface it is being attached to.";
    case DDERR_SURFACEALREADYDEPENDENT:
      return "This surface is already a dependency of the surface it is being made a dependency of.";
    case DDERR_SURFACEBUSY:
      return "Access to this surface is being refused because the surface is already locked by another thread.";
    case DDERR_SURFACEISOBSCURED:
      return "Access to surface refused because the surface is obscured.";
    case DDERR_SURFACELOST:
      return "Access to this surface is being refused because the surface memory is gone. The DirectDrawSurface object representing this surface should have Restore called on it.";
    case DDERR_SURFACENOTATTACHED:
      return "The requested surface is not attached.";
    case DDERR_TOOBIGHEIGHT:
      return "Height requested by DirectDraw is too large.";
    case DDERR_TOOBIGSIZE:
      return "Size requested by DirectDraw is too large, but the individual height and width are OK.";
    case DDERR_TOOBIGWIDTH:
      return "Width requested by DirectDraw is too large.";
    case DDERR_UNSUPPORTED:
      return "Action not supported.";
    case DDERR_UNSUPPORTEDFORMAT:
      return "FOURCC format requested is unsupported by DirectDraw.";
    case DDERR_UNSUPPORTEDMASK:
      return "Bitmask in the pixel format requested is unsupported by DirectDraw.";
    case DDERR_VERTICALBLANKINPROGRESS:
      return "Vertical blank is in progress.";
    case DDERR_WASSTILLDRAWING:
      return "Informs DirectDraw that the previous Blt which is transfering information to or from this Surface is incomplete.";
    case DDERR_WRONGMODE:
      return "This surface can not be restored because it was created in a different mode.";
    case DDERR_XALIGN:
      return "Rectangle provided was not horizontally aligned on required boundary.";
    default:
      return "Unrecognized error value.";
  }
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
  Mode mode = { width, height, bpp };
  int i;

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

  if (m_bPrimaryPalettized)
  {
    if (m_pPalette)
    {
      result = m_pPalette->SetEntries(0, 0, 256, m_originalPaletteEntries);
      if (result != DD_OK)
      {
        Error("SetEntries failed", result);
        return FALSE;
      }
    }
  }

  return TRUE;
}

// OFFSET: LEGO1 0x1009E750
BOOL MxDirectDraw::RestorePaletteEntries()
{
  HRESULT result;

  if (m_bFullScreen && m_bPrimaryPalettized)
  {
    if (m_pPalette)
    {
      result = m_pPalette->SetEntries(0, 0, _countof(m_paletteEntries), m_paletteEntries);
      if (result != DD_OK)
      {
        Error("SetEntries failed", result);
        return FALSE;
      }
    }
  }

  return TRUE;
}

// OFFSET: LEGO1 0x1009e7f0
int MxDirectDraw::FlipToGDISurface()
{
  HRESULT ret;

  if (m_pDirectDraw)
  {
    ret = m_pDirectDraw->FlipToGDISurface();
    if (ret != DD_OK)
    {
      Error("FlipToGDISurface failed", ret);
    }
    return !ret;
  }

  return 1;
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
    for (i = 10; (i < paletteEntryCount) && (i < 246); i++)
    {
	  m_paletteEntries[i].peRed = pPaletteEntries[i].peRed;
	  m_paletteEntries[i].peGreen = pPaletteEntries[i].peGreen;
	  m_paletteEntries[i].peBlue = pPaletteEntries[i].peBlue;
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
  int i;
  unsigned int j;
  int count = m_bFlipSurfaces ? 2 : 1;

  for (i = 0; count > i; i++)
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
    for (j = ddsd.dwHeight - 1; j ; j--)
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

