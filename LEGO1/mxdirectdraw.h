#ifndef MXDIRECTDRAW_H
#define MXDIRECTDRAW_H

#include <ddraw.h>
#include <Windows.h>

class MxDirectDraw
{
public:
  HRESULT SetEntries();
  __declspec(dllexport) HRESULT FlipToGDISurface();
  void FUN_1009e830(char *, HRESULT);
  __declspec(dllexport) static int GetPrimaryBitDepth();
  __declspec(dllexport) int Pause(int);
  HRESULT FUN_1009e750();

  virtual ~MxDirectDraw();
  virtual void vtable04();
  virtual void vtable08();
  virtual void vtable0c();
  virtual char * ErrorToString(HRESULT);

private:
  IDirectDraw *m_ddraw; // +0xc
  IDirectDrawPalette *m_ddpal; // +0x28
  PALETTEENTRY m_pal0[256]; // +0x2c
  PALETTEENTRY m_pal1[256]; // +0x42c
  HWND hWindow; // +0x83c
  BOOL m_paletteIndexed8;
  BOOL m_fullScreen;
  void (*m_unk85c)(char *, HRESULT, long); // error handler or logger?
  long m_unk864;
  long m_unk86c;

};

#endif // MXDIRECTDRAW_H
