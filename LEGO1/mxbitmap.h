#ifndef MXBITMAP_H
#define MXBITMAP_H

#include <stdlib.h>

#include "mxcore.h"
#include "mxpalette.h"
#include "mxtypes.h"

class MxBitmap : public MxCore
{
public:
  __declspec(dllexport) MxBitmap();
  __declspec(dllexport) virtual ~MxBitmap(); // vtable+00

  virtual int vtable14(int);
  virtual MxResult vtable18(BITMAPINFOHEADER *p_bmiHeader);
  virtual int vtable1c(int p_width, int p_height, MxPalette *p_palette, int);
  virtual MxResult LoadFile(HANDLE p_handle);
  __declspec(dllexport) virtual MxLong Read(const char *p_filename); // vtable+24
  virtual int vtable28(int);
  virtual void vtable2c(int, int, int, int, int, int, int);
  virtual void vtable30(int, int, int, int, int, int, int);
  __declspec(dllexport) virtual MxPalette *CreatePalette(); // vtable+34
  virtual void vtable38(void*);
  virtual int vtable3c(MxBool);
  virtual MxResult CopyColorData(HDC p_hdc, int p_xSrc, int p_ySrc, int p_xDest, int p_yDest, int p_destWidth, int p_destHeight); // vtable+40

private:
  BITMAPINFO *m_info; // 0x8
  BITMAPINFOHEADER *m_bmiHeader; // 0xc
  RGBQUAD *m_paletteData; // 0x10
  LPVOID *m_data; // 0x14
  MxBool m_bmiColorsProvided; // 0x18
  MxPalette *m_palette; // 0x1c
};

#endif // MXBITMAP_H
