#include "mxbitmap.h"
#include "decomp.h"

DECOMP_SIZE_ASSERT(MxBITMAPINFO, 1064);

// The way that the BITMAPFILEHEADER structure ensures the file type is by ensuring it is "BM", which is literally just 0x424d.
// Sources: https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapfileheader, DirectX Complete (1998)
// GLOBAL: LEGO1 0x10102184
undefined2 g_bitmapSignature = 0x424d;

// OFFSET: LEGO1 0x100bc980
MxBitmap::MxBitmap()
{
  this->m_info = NULL;
  this->m_bmiHeader = NULL;
  this->m_paletteData = NULL;
  this->m_data = NULL;
  this->m_bitDepth = LOWCOLOR;
  this->m_palette = NULL;
}

// OFFSET: LEGO1 0x100bca10
MxBitmap::~MxBitmap()
{
  if (this->m_info)
    delete m_info;
  if (this->m_data)
    delete m_data;
  if (this->m_palette)
    delete m_palette;  
}

// OFFSET: LEGO1 0x100bcc40
MxResult MxBitmap::vtable14(MxBitmap *p_bitmap)
{
  MxLong height;
  MxResult result = FAILURE;

  this->m_info = new MxBITMAPINFO;
  if(this->m_info) {
    height = p_bitmap->m_bmiHeader->biHeight;
    if (height <= 0L) {
      height = -height;
    }
    this->m_data = (LPVOID*) new MxU8[(p_bitmap->m_bmiHeader->biWidth + 3U & -4) * height];
    if(this->m_data) {
      memcpy(this->m_info, p_bitmap->m_info, sizeof(MxBITMAPINFO));

      height = p_bitmap->m_bmiHeader->biHeight;
      if (height <= 0L) {
        height = -height;
      }
      memcpy(this->m_data, p_bitmap->m_data, (p_bitmap->m_bmiHeader->biWidth + 3U & -4) * height);

      result = SUCCESS;
      this->m_bmiHeader = &this->m_info->bmiHeader;
      this->m_paletteData = this->m_info->bmiColors;
    }
  }
  if (result != SUCCESS) {
    if (this->m_info) {
      delete this->m_info;
      this->m_info = NULL;
    }
    if (this->m_data) {
      delete this->m_data;
      this->m_data = NULL;
    }
  }
  return result;
}

// OFFSET: LEGO1 0x100bcba0
MxResult MxBitmap::vtable18(MxBITMAPINFO *p_info)
{
  MxResult result = FAILURE;
  MxLong width  = p_info->bmiHeader.biWidth;
  MxLong height = p_info->bmiHeader.biHeight;
  // ((width + 3) & -4) clamps width to nearest 4-byte boundary
  MxLong size = ((width + 3) & -4) * height;

  this->m_info = new MxBITMAPINFO;
  if (this->m_info) {
    this->m_data = (LPVOID*) new MxU8[size];
    if(this->m_data) {
      memcpy(this->m_info, p_info, sizeof(MxBITMAPINFO));
      this->m_bmiHeader = &this->m_info->bmiHeader;
      this->m_paletteData = this->m_info->bmiColors;
      result = SUCCESS;
    }
  }
  if (result != SUCCESS) {
    if (this->m_info) {
      delete this->m_info;
      this->m_info = NULL;
    }
    if (this->m_data) {
      delete this->m_data;
      this->m_data = NULL;
    }
  }
  return result;
}


// OFFSET: LEGO1 0x100bd450
MxResult MxBitmap::ImportColorsToPalette(RGBQUAD* p_rgbquad, MxPalette* p_palette)
{
  MxResult ret = FAILURE;
  PALETTEENTRY entries[256];

  if (p_palette) {
    if (p_palette->GetEntries(entries))
      return ret;
  } else {
    MxPalette local_pal;
    if (local_pal.GetEntries(entries))
      return ret;
  }

  for (int i = 0; i < 256; i++) {
    p_rgbquad[i].rgbRed      = entries[i].peRed;
    p_rgbquad[i].rgbGreen    = entries[i].peGreen;
    p_rgbquad[i].rgbBlue     = entries[i].peBlue;
    p_rgbquad[i].rgbReserved = 0;
  }

  ret = SUCCESS;
  return ret;
}

// OFFSET: LEGO1 0x100bcaa0
MxResult MxBitmap::vtable1c(int p_width, int p_height, MxPalette *p_palette, int p_bitDepth)
{
  MxResult ret = FAILURE;
  MxLong size = ((p_width + 3) & -4) * p_height;

  m_info = new MxBITMAPINFO;
  if (m_info) {
    m_data = (LPVOID*) new MxU8[size];
    if (m_data) {
      m_bmiHeader = &m_info->bmiHeader;
      m_paletteData = m_info->bmiColors;
      memset(&m_info->bmiHeader, 0, sizeof(m_info->bmiHeader));

      m_bmiHeader->biSize = sizeof(*m_bmiHeader); // should be 40 bytes
      m_bmiHeader->biWidth = p_width;
      m_bmiHeader->biHeight = p_height;
      m_bmiHeader->biPlanes = 1;
      m_bmiHeader->biBitCount = 8;
      m_bmiHeader->biCompression = 0;
      m_bmiHeader->biSizeImage = size;

      if (!ImportColorsToPalette(m_paletteData, p_palette)) {
        if (!vtable3c(p_bitDepth)) {
          ret = SUCCESS;
        }
      }
    }
  }

  if (ret) {
    if (m_info) {
      delete m_info;
      m_info = NULL;
    }

    if (m_data) {
      delete[] m_data;
      m_data = NULL;
    }
  }

  return ret;
}

// OFFSET: LEGO1 0x100bcd60
MxResult MxBitmap::LoadFile(HANDLE p_handle)
{
  BOOL ret;
  LPVOID* lpBuffer;
  MxLong height;
  MxResult result = FAILURE;
  DWORD bytesRead;
  BITMAPFILEHEADER hdr;
  MxLong size;

  ret = ReadFile(p_handle, &hdr, sizeof(hdr), &bytesRead, NULL);
  if (ret && (hdr.bfType == g_bitmapSignature)) {
    this->m_info = new MxBITMAPINFO;
    if(this->m_info) {
      ret = ReadFile(p_handle, this->m_info, sizeof(MxBITMAPINFO), &bytesRead, NULL);
      if (ret && ((this->m_info->bmiHeader).biBitCount == 8)) {
        size = hdr.bfSize - (sizeof(MxBITMAPINFO) + sizeof(BITMAPFILEHEADER));
        lpBuffer = (LPVOID*) new MxU8[size];
        this->m_data = lpBuffer;
        if (lpBuffer) {
          ret = ReadFile(p_handle, lpBuffer, size, &bytesRead, NULL);
          if(ret) {
            this->m_bmiHeader = &this->m_info->bmiHeader;
            this->m_paletteData = this->m_info->bmiColors;
            if((this->m_info->bmiHeader).biSizeImage == 0) {
              height = (this->m_info->bmiHeader).biHeight;
              if (height <= 0L) {
                height = -height;
              }
              (this->m_info->bmiHeader).biSizeImage = ((this->m_info->bmiHeader).biWidth + 3U & -4) * height;
            }
            result = SUCCESS;
          }
        }
      }
    }
  }
  if (result != SUCCESS) {
    if (this->m_info) {
      delete this->m_info;
      this->m_info = NULL;
    }
    if (this->m_data) {
      delete this->m_data;
      this->m_data = NULL;
    }
  }
  return result;
}

// OFFSET: LEGO1 0x100bcd10
MxLong MxBitmap::Read(const char *p_filename)
{
  MxResult result = FAILURE;
  HANDLE handle = CreateFileA(
    p_filename,
    GENERIC_READ,
    FILE_SHARE_READ,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    NULL
  );

  if (handle != INVALID_HANDLE_VALUE && !LoadFile(handle))
    result = SUCCESS;

  if (handle)
    CloseHandle(handle);

  return result;
}

// OFFSET: LEGO1 0x1004e0d0
int MxBitmap::vtable28(int)
{
  return -1;
}

// OFFSET: LEGO1 0x100bce70 STUB
void MxBitmap::vtable2c(int, int, int, int, int, int, int)
{
}

// OFFSET: LEGO1 0x100bd020 STUB
void MxBitmap::vtable30(int, int, int, int, int, int, int)
{
}

// OFFSET: LEGO1 0x100bd1c0
MxPalette *MxBitmap::CreatePalette()
{
  MxBool success = FALSE;
  MxPalette *palette = NULL;

  switch (this->m_bitDepth) {
    case LOWCOLOR:
      palette = new MxPalette(this->m_paletteData);
      if (palette)
        success = TRUE;
      break;

    case HIGHCOLOR:
      palette = this->m_palette->Clone();
      if (palette)
        success = TRUE;
      break;
  }

  if (!success && palette) {
    delete palette;
    palette = NULL;
  }

  return palette;
}

// OFFSET: LEGO1 0x100bd280
void MxBitmap::ImportPalette(MxPalette* p_palette)
{
  // This is weird but it matches. Maybe m_bmiColorsProvided had more
  // potential values than just true/false at some point?
  switch (this->m_bitDepth) {
    case LOWCOLOR:
      ImportColorsToPalette(this->m_paletteData, p_palette);
      break;
    
    case HIGHCOLOR:
      if (this->m_palette) {
        delete this->m_palette;
      }
      this->m_palette = p_palette->Clone();
      break;
  }
}

// OFFSET: LEGO1 0x100bd2d0
MxResult MxBitmap::vtable3c(MxBool p_bitDepth)
{
  MxResult ret = FAILURE;
  MxPalette *pal = NULL;

  if (m_bitDepth == p_bitDepth) {
    // no change: do nothing.
    ret = SUCCESS;
  } else {
    // TODO: Another switch used for this boolean value? Is it not a bool?
    switch (p_bitDepth) {
      case 0:
        ImportColorsToPalette(m_paletteData, m_palette);
        if (m_palette)
          delete m_palette;

        m_palette = NULL;
        break;

      case 1:
        pal = NULL;
        pal = new MxPalette(m_paletteData);
        if (pal) {
          m_palette = pal;

          // TODO: what is this? zeroing out top half of palette?
          MxU16 *buf = (MxU16*)m_paletteData;
          for (MxU16 i = 0; i < 256; i++) {
            buf[i] = i;
          }

          m_bitDepth = p_bitDepth;
          ret = SUCCESS;
        }
        break;
    }
  }

  // If we were unsuccessful overall but did manage to alloc
  // the MxPalette, free it.
  if (ret && pal)
    delete pal;

  return ret;
}

// OFFSET: LEGO1 0x100bd3e0
MxResult MxBitmap::CopyColorData(HDC p_hdc, int p_xSrc, int p_ySrc, int p_xDest, int p_yDest, int p_destWidth, int p_destHeight)
{
  // Compression fix?
  if ((this->m_bmiHeader->biCompression != 16) && (0 < this->m_bmiHeader->biHeight)) {
    p_ySrc = (this->m_bmiHeader->biHeight - p_destHeight) - p_ySrc;
  }

  return StretchDIBits(p_hdc, p_xDest, p_yDest, p_destWidth, p_destHeight, p_xSrc, p_ySrc, p_destWidth, p_destHeight, this->m_data, (BITMAPINFO*)this->m_info, this->m_bitDepth, SRCCOPY);
}