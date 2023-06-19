#pragma comment(lib, "ddraw")

#include "mxdirectdraw.h"

// 0x10100c68
BOOL g_paletteIndexed8 = 0;

// 0x10100c70
BOOL DAT_10100c70 = 0;

// OFFSET: LEGO1 0x1009e7a0
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

// OFFSET: LEGO1 0x1009e7f0
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

// OFFSET: LEGO1 0x1009e830
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
    g_paletteIndexed8 = (ddsd.ddpfPixelFormat.dwFlags & DDPF_PALETTEINDEXED8) != 0;
    pDDraw->Release();
  }

  return dwRGBBitCount;
}

// OFFSET: LEGO1 0x1009e6a0
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

// OFFSET: LEGO1 0x1009e750
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

// OFFSET: LEGO1 0x1009e880
char * MxDirectDraw::ErrorToString(HRESULT error)
{
  switch(error) {
    case DD_OK:
      return "No error.\0";
    case DDERR_ALREADYINITIALIZED:
      return "This object is already initialized.\0";
    case DDERR_BLTFASTCANTCLIP:
      return "Return if a clipper object is attached to the source surface passed into a BltFast call.\0";
    case DDERR_CANNOTATTACHSURFACE:
      return "This surface can not be attached to the requested surface.\0";
    case DDERR_CANNOTDETACHSURFACE:
      return "This surface can not be detached from the requested surface.\0";
    case DDERR_CANTCREATEDC:
      return "Windows can not create any more DCs.\0";
    case DDERR_CANTDUPLICATE:
      return "Can't duplicate primary & 3D surfaces, or surfaces that are implicitly created.\0";
    case DDERR_CLIPPERISUSINGHWND:
      return "An attempt was made to set a cliplist for a clipper object that is already monitoring an hwnd.\0";
    case DDERR_COLORKEYNOTSET:
      return "No src color key specified for this operation.\0";
    case DDERR_CURRENTLYNOTAVAIL:
      return "Support is currently not available.\0";
    case DDERR_DIRECTDRAWALREADYCREATED:
      return "A DirectDraw object representing this driver has already been created for this process.\0";
    case DDERR_EXCEPTION:
      return "An exception was encountered while performing the requested operation.\0";
    case DDERR_EXCLUSIVEMODEALREADYSET:
      return "An attempt was made to set the cooperative level when it was already set to exclusive.\0";
    case DDERR_GENERIC:
      return "Generic failure.\0";
    case DDERR_HEIGHTALIGN:
      return "Height of rectangle provided is not a multiple of reqd alignment.\0";
    case DDERR_HWNDALREADYSET:
      return "The CooperativeLevel HWND has already been set. It can not be reset while the process has surfaces or palettes created.\0";
    case DDERR_HWNDSUBCLASSED:
      return "HWND used by DirectDraw CooperativeLevel has been subclassed, this prevents DirectDraw from restoring state.\0";
    case DDERR_IMPLICITLYCREATED:
      return "This surface can not be restored because it is an implicitly created surface.\0";
    case DDERR_INCOMPATIBLEPRIMARY:
      return "Unable to match primary surface creation request with existing primary surface.\0";
    case DDERR_INVALIDCAPS:
      return "One or more of the caps bits passed to the callback are incorrect.\0";
    case DDERR_INVALIDCLIPLIST:
      return "DirectDraw does not support the provided cliplist.\0";
    case DDERR_INVALIDDIRECTDRAWGUID:
      return "The GUID passed to DirectDrawCreate is not a valid DirectDraw driver identifier.\0";
    case DDERR_INVALIDMODE:
      return "DirectDraw does not support the requested mode.\0";
    case DDERR_INVALIDOBJECT:
      return "DirectDraw received a pointer that was an invalid DIRECTDRAW object.\0";
    case DDERR_INVALIDPARAMS:
      return "One or more of the parameters passed to the function are incorrect.\0";
    case DDERR_INVALIDPIXELFORMAT:
      return "The pixel format was invalid as specified.\0";
    case DDERR_INVALIDPOSITION:
      return "Returned when the position of the overlay on the destination is no longer legal for that destination.\0";
    case DDERR_INVALIDRECT:
      return "Rectangle provided was invalid.\0";
    case DDERR_LOCKEDSURFACES:
      return "Operation could not be carried out because one or more surfaces are locked.\0";
    case DDERR_NO3D:
      return "There is no 3D present.\0";
    case DDERR_NOALPHAHW:
      return "Operation could not be carried out because there is no alpha accleration hardware present or available.\0";
    case DDERR_NOBLTHW:
      return "No blitter hardware present.\0";
    case DDERR_NOCLIPLIST:
      return "No cliplist available.\0";
    case DDERR_NOCLIPPERATTACHED:
      return "No clipper object attached to surface object.\0";
    case DDERR_NOCOLORCONVHW:
      return "Operation could not be carried out because there is no color conversion hardware present or available.\0";
    case DDERR_NOCOLORKEY:
      return "Surface doesn't currently have a color key\0";
    case DDERR_NOCOLORKEYHW:
      return "Operation could not be carried out because there is no hardware support of the destination color key.\0";
    case DDERR_NOCOOPERATIVELEVELSET:
      return "Create function called without DirectDraw object method SetCooperativeLevel being called.\0";
    case DDERR_NODC:
      return "No DC was ever created for this surface.\0";
    case DDERR_NODDROPSHW:
      return "No DirectDraw ROP hardware.\0";
    case DDERR_NODIRECTDRAWHW:
      return "A hardware-only DirectDraw object creation was attempted but the driver did not support any hardware.\0";
    case DDERR_NOEMULATION:
      return "Software emulation not available.\0";
    case DDERR_NOEXCLUSIVEMODE:
      return "Operation requires the application to have exclusive mode but the application does not have exclusive mode.\0";
    case DDERR_NOFLIPHW:
      return "Flipping visible surfaces is not supported.\0";
    case DDERR_NOGDI:
      return "There is no GDI present.\0";
    case DDERR_NOHWND:
      return "Clipper notification requires an HWND or no HWND has previously been set as the CooperativeLevel HWND.\0";
    case DDERR_NOMIRRORHW:
      return "Operation could not be carried out because there is no hardware present or available.\0";
    case DDERR_NOOVERLAYDEST:
      return "Returned when GetOverlayPosition is called on an overlay that UpdateOverlay has never been called on to establish a destination.\0";
    case DDERR_NOOVERLAYHW:
      return "Operation could not be carried out because there is no overlay hardware present or available.\0";
    case DDERR_NOPALETTEATTACHED:
      return "No palette object attached to this surface.\0";
    case DDERR_NOPALETTEHW:
      return "No hardware support for 16 or 256 color palettes.\0";
    case DDERR_NORASTEROPHW:
      return "Operation could not be carried out because there is no appropriate raster op hardware present or available.\0";
    case DDERR_NOROTATIONHW:
      return "Operation could not be carried out because there is no rotation hardware present or available.\0";
    case DDERR_NOSTRETCHHW:
      return "Operation could not be carried out because there is no hardware support for stretching.\0";
    case DDERR_NOT4BITCOLOR:
      return "DirectDrawSurface is not in 4 bit color palette and the requested operation requires 4 bit color palette.\0";
    case DDERR_NOT4BITCOLORINDEX:
      return "DirectDrawSurface is not in 4 bit color index palette and the requested operation requires 4 bit color index palette.\0";
    case DDERR_NOT8BITCOLOR:
      return "DirectDrawSurface is not in 8 bit color mode and the requested operation requires 8 bit color.\0";
    case DDERR_NOTAOVERLAYSURFACE:
      return "Returned when an overlay member is called for a non-overlay surface.\0";
    case DDERR_NOTEXTUREHW:
      return "Operation could not be carried out because there is no texture mapping hardware present or available.\0";
    case DDERR_NOTFLIPPABLE:
      return "An attempt has been made to flip a surface that is not flippable.\0";
    case DDERR_NOTFOUND:
      return "Requested item was not found.\0";
    case DDERR_NOTLOCKED:
      return "Surface was not locked.  An attempt to unlock a surface that was not locked at all, or by this process, has been attempted.\0";
    case DDERR_NOTPALETTIZED:
      return "The surface being used is not a palette-based surface.\0";
    case DDERR_NOVSYNCHW:
      return "Operation could not be carried out because there is no hardware support for vertical blank synchronized operations.\0";
    case DDERR_NOZBUFFERHW:
      return "Operation could not be carried out because there is no hardware support for zbuffer blitting.\0";
    case DDERR_NOZOVERLAYHW:
      return "Overlay surfaces could not be z layered based on their BltOrder because the hardware does not support z layering of overlays.\0";
    case DDERR_OUTOFCAPS:
      return "The hardware needed for the requested operation has already been allocated.\0";
    case DDERR_OUTOFMEMORY:
      return "DirectDraw does not have enough memory to perform the operation.\0";
    case DDERR_OUTOFVIDEOMEMORY:
      return "DirectDraw does not have enough memory to perform the operation.\0";
    case DDERR_OVERLAYCANTCLIP:
      return "The hardware does not support clipped overlays.\0";
    case DDERR_OVERLAYCOLORKEYONLYONEACTIVE:
      return "Can only have ony color key active at one time for overlays.\0";
    case DDERR_OVERLAYNOTVISIBLE:
      return "Returned when GetOverlayPosition is called on a hidden overlay.\0";
    case DDERR_PALETTEBUSY:
      return "Access to this palette is being refused because the palette is already locked by another thread.\0";
    case DDERR_PRIMARYSURFACEALREADYEXISTS:
      return "This process already has created a primary surface.\0";
    case DDERR_REGIONTOOSMALL:
      return "Region passed to Clipper::GetClipList is too small.\0";
    case DDERR_SURFACEALREADYATTACHED:
      return "This surface is already attached to the surface it is being attached to.\0";
    case DDERR_SURFACEALREADYDEPENDENT:
      return "This surface is already a dependency of the surface it is being made a dependency of.\0";
    case DDERR_SURFACEBUSY:
      return "Access to this surface is being refused because the surface is already locked by another thread.\0";
    case DDERR_SURFACEISOBSCURED:
      return "Access to surface refused because the surface is obscured.\0";
    case DDERR_SURFACELOST:
      return "Access to this surface is being refused because the surface memory is gone. The DirectDrawSurface object representing this surface should have Restore called on it.\0";
    case DDERR_SURFACENOTATTACHED:
      return "The requested surface is not attached.\0";
    case DDERR_TOOBIGHEIGHT:
      return "Height requested by DirectDraw is too large.\0";
    case DDERR_TOOBIGSIZE:
      return "Size requested by DirectDraw is too large, but the individual height and width are OK.\0";
    case DDERR_TOOBIGWIDTH:
      return "Width requested by DirectDraw is too large.\0";
    case DDERR_UNSUPPORTED:
      return "Action not supported.\0";
    case DDERR_UNSUPPORTEDFORMAT:
      return "FOURCC format requested is unsupported by DirectDraw.\0";
    case DDERR_UNSUPPORTEDMASK:
      return "Bitmask in the pixel format requested is unsupported by DirectDraw.\0";
    case DDERR_VERTICALBLANKINPROGRESS:
      return "Vertical blank is in progress.\0";
    case DDERR_WASSTILLDRAWING:
      return "Informs DirectDraw that the previous Blt which is transfering information to or from this Surface is incomplete.\0";
    case DDERR_WRONGMODE:
      return "This surface can not be restored because it was created in a different mode.\0";
    case DDERR_XALIGN:
      return "Rectangle provided was not horizontally aligned on required boundary.\0";
    default:
      return "Unrecognized error value.\0";
  }
}
