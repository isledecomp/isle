#include "mxbitmap.h"

// OFFSET: LEGO1 0x100bc980
MxBitmap::MxBitmap()
{
  this->m_info = NULL;
  this->m_bmiHeader = NULL;
  this->m_paletteData = NULL;
  this->m_data = NULL;
  this->m_unk18 = FALSE;
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

// OFFSET: LEGO1 0x100bcba0 STUB
int MxBitmap::vtable18(BITMAPINFOHEADER *p_bmiHeader)
{
  return 0;
}

// OFFSET: LEGO1 0x100bcaa0 STUB
int MxBitmap::vtable1c(int p_width, int p_height, MxPalette *p_palette, int)
{
  return 0;
}

// OFFSET: LEGO1 0x100bcd60 STUB
MxResult MxBitmap::LoadFile(HANDLE p_handle)
{
  return SUCCESS;
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

// OFFSET: LEGO1 0x100ce70 STUB
void MxBitmap::vtable2c(int, int, int, int, int, int, int)
{
}

// OFFSET: LEGO1 0x100d020 STUB
void MxBitmap::vtable30(int, int, int, int, int, int, int)
{
}

// OFFSET: LEGO1 0x100bd1c0
MxPalette *MxBitmap::CreatePalette()
{
  // FIXME: This function needs MxPalette to be completed. Also INFERRING usage of MxBool
  MxPalette *pal = NULL;
  MxPalette *ppal;
  MxBool success = FALSE;

  if(this->m_unk18 == FALSE) {
    // ppal = MxPalette::FromBitmapPalette(this->m_paletteData);
  } else {
    if(this->m_unk18 != TRUE) {
      if(!success && pal != NULL) {
        delete pal;
        pal = NULL;
      }
    }
    //.pal = MxPalette::Clone(this->m_palette);
  }
  if(pal != NULL) {
    success = TRUE;
  }

  return pal;
}

// OFFSET: LEGO1 0x100bd280 STUB
void MxBitmap::vtable38(void*)
{
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

  return StretchDIBits(p_hdc, p_xDest, p_yDest, p_destWidth, p_destHeight, p_xSrc, p_ySrc, p_destWidth, p_destHeight, this->m_data, this->m_info, this->m_unk18, SRCCOPY);
}