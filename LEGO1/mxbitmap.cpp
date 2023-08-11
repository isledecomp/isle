#include "mxbitmap.h"

// The way that the BITMAPFILEHEADER structure ensures the file type is by ensuring it is "BM", which is literally just 0x424d.
// Sources: https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapfileheader, DirectX Complete (1998)
// GLOBAL: LEGO1 0x10102184
DWORD g_bitmapSignature = 0x424d;

// OFFSET: LEGO1 0x100bc980
MxBitmap::MxBitmap()
{
  this->m_info = NULL;
  this->m_bmiHeader = NULL;
  this->m_paletteData = NULL;
  this->m_data = NULL;
  this->m_bmiColorsProvided = FALSE;
  this->m_palette = NULL;
}

// OFFSET: LEGO1 0x100bca10
MxBitmap::~MxBitmap()
{
  if (this->m_info != NULL)
    delete m_info;
  if (this->m_data != NULL)
    delete m_data;
  if (this->m_palette != NULL)
    delete m_palette;  
}

// OFFSET: LEGO1 0x100bcc40 STUB
int MxBitmap::vtable14(int)
{
  return 0;
}

// OFFSET: LEGO1 0x100bcba0
MxResult MxBitmap::vtable18(BITMAPINFOHEADER *p_bmiHeader)
{
  MxResult result = FAILURE;
  int width = p_bmiHeader->biWidth;
  int height = p_bmiHeader->biHeight;

  this->m_info = (BITMAPINFO*) malloc(0x428);
  if (this->m_info != NULL) {
    this->m_data = (LPVOID*) malloc((width + 3 & -4) * height);
    if(this->m_data != NULL) {
      memcpy(&this->m_info->bmiHeader, p_bmiHeader, 266);
      this->m_bmiHeader = &this->m_info->bmiHeader;
      this->m_paletteData = this->m_info->bmiColors;
      result = SUCCESS;
    }
  }
  if (result != SUCCESS) {
    if (this->m_info != NULL) {
      delete this->m_info;
      this->m_info = NULL;
    }
    if (this->m_data != NULL) {
      delete this->m_data;
      this->m_data = NULL;
    }
  }
  return result;
}


// OFFSET: LEGO1 0x100bd450
MxResult ImportColorsToPalette(RGBQUAD* p_rgbquad, MxPalette* p_palette)
{
  MxPalette* local_pal;
  MxResult ret = FAILURE;
  PALETTEENTRY entries[256];
  MxResult opret;

  if(p_palette == NULL) {
    local_pal = new MxPalette;
    opret = local_pal->GetEntries(entries);
    if(opret != 0) {
      delete local_pal;
      return ret;
    }
  } else {
    opret = p_palette->GetEntries(entries);
    if(opret != 0) return ret;
  }

  // FIXME/TODO: the loop here, possibly memcpy
  ret = SUCCESS;
  return ret;
}

// OFFSET: LEGO1 0x100bcaa0 STUB
int MxBitmap::vtable1c(int p_width, int p_height, MxPalette *p_palette, int)
{
  return 0;
}

// OFFSET: LEGO1 0x100bcd60
MxResult MxBitmap::LoadFile(HANDLE p_handle)
{
  LPVOID* lpBuffer;
  MxS32 height;
  MxBool ret;
  MxResult result = FAILURE;
  DWORD bytesRead;
  BITMAPFILEHEADER hdr;

  ret = ReadFile(p_handle, &hdr, sizeof(hdr), &bytesRead, NULL);
  if (ret && (hdr.bfType == g_bitmapSignature)) {
    this->m_info = (BITMAPINFO*) malloc(1064);
    if(this->m_info != NULL) {
      ret = ReadFile(p_handle, this->m_info, 1064, &bytesRead, NULL);
      if (ret && ((this->m_info->bmiHeader).biBitCount == 8)) {
        lpBuffer = (LPVOID*) malloc(hdr.bfSize - 1078);
        this->m_data = lpBuffer;
        if (this->m_data != NULL) {
          ret = ReadFile(p_handle, lpBuffer, hdr.bfSize - 1078, &bytesRead, NULL);
          if(ret != 0) {
            this->m_bmiHeader = &this->m_info->bmiHeader;
            this->m_paletteData = this->m_info->bmiColors;
            if((this->m_info->bmiHeader).biSizeImage == 0) {
              height = (this->m_info->bmiHeader).biHeight;
              if (height < 1) {
                height *= -1;
              }
              (this->m_info->bmiHeader).biSizeImage = ((this->m_info->bmiHeader).biWidth + 3U & 0xfffffffc) * height;
            }
            result = SUCCESS;
          }
        }
      }
    }
  }
  if (result != SUCCESS) {
    if (this->m_info != NULL) {
      delete this->m_info;
      this->m_info = NULL;
    }
    if (this->m_data != NULL) {
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
  // FIXME: doesn't match
  MxPalette *pal;
  MxPalette *ppal;
  MxBool success;

  pal = NULL;
  success = FALSE;
  if(this->m_bmiColorsProvided == FALSE) {
    ppal = new MxPalette(this->m_paletteData);
    if (ppal != NULL) {
      pal = ppal;
    }
  } else {
    if(this->m_bmiColorsProvided != TRUE) {
      if(!success && pal != NULL) {
        delete pal;
        pal = NULL;
      }
    }
    pal = this->m_palette->Clone();
  }
  if(pal != NULL) {
    success = TRUE;
  }

  return pal;
}

// OFFSET: LEGO1 0x100bd280
void MxBitmap::ImportPalette(MxPalette* p_palette)
{
  if (this->m_bmiColorsProvided) {
    ImportColorsToPalette(this->m_paletteData, p_palette);
  }
  if (this->m_palette != NULL) {
    delete this->m_palette;
  }
  this->m_palette = p_palette->Clone();
}

// OFFSET: LEGO1 0x100bd2d0 STUB
int MxBitmap::vtable3c(MxBool)
{
  return 0;
}

// OFFSET: LEGO1 0x100bd3e0
MxResult MxBitmap::CopyColorData(HDC p_hdc, int p_xSrc, int p_ySrc, int p_xDest, int p_yDest, int p_destWidth, int p_destHeight)
{
  // Compression fix?
  if ((this->m_bmiHeader->biCompression != 16) && (0 < this->m_bmiHeader->biHeight)) {
    p_ySrc = (this->m_bmiHeader->biHeight - p_destHeight) - p_ySrc;
  }

  return StretchDIBits(p_hdc, p_xDest, p_yDest, p_destWidth, p_destHeight, p_xSrc, p_ySrc, p_destWidth, p_destHeight, this->m_data, this->m_info, this->m_bmiColorsProvided, SRCCOPY);
}