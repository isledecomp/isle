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
  if (this->m_info != NULL) {
    delete m_info;
  }
  if (this->m_data != NULL) {
    delete m_data;
  }
  if (this->m_palette != NULL) {
    delete m_palette;  
  }
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

// OFFSET: LEGO1 0x100bcd10
long MxBitmap::Read(const char *filename)
{
  HANDLE handle;
  int unk1;
  MxResult ret = FAILURE;

  handle = CreateFileA(filename,GENERIC_READ,FILE_SHARE_READ,(LPSECURITY_ATTRIBUTES)NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,(HANDLE)NULL);
  if(handle != (HANDLE)INVALID_HANDLE_VALUE) {  // INVALID_HANDLE_VALUE = -1, or 0xffffffff
		// FIXME: line 16. iVar gets changed in this line
    if(unk1 == 0) {
      ret = SUCCESS;
    }
  }
  if(handle != (HANDLE)NULL) {
    CloseHandle(handle);
  }

  return ret;
}

