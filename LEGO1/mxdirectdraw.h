
#ifndef MXDIRECTDRAW_H
#define MXDIRECTDRAW_H

#include <ddraw.h>
#include <Windows.h>

extern BOOL g_is_PALETTEINDEXED8;

//size 0x880
class MxDirectDraw
{
public:
  typedef void (*ErrorHandler)(const char*, HRESULT, void*);

  //size 0x0c
  struct Mode
  {
    int width;
    int height;
    int bitsPerPixel;

    int operator==(const Mode& rMode) const
    {
      return ((width == rMode.width) &&
        (height == rMode.height) &&
        (bitsPerPixel == rMode.bitsPerPixel));
    }
  };

  //size 0x17c
  struct DeviceModesInfo
  {
    GUID* p_guid;
    Mode* m_mode_ARRAY;
    int count;
    DDCAPS_DX5 m_ddcaps;
    void* a_178;

    ~DeviceModesInfo()
    {
      if (p_guid != NULL)
      {
        free(p_guid);
      }

      if (m_mode_ARRAY != NULL)
      {
        free(m_mode_ARRAY);
      }
    }
  };


private:
  BOOL m_bOnlySoftRender;
  BOOL m_bFlipSurfaces;
  IDirectDraw* m_pDirectDraw;
  IDirectDrawSurface* m_pFrontBuffer;
  IDirectDrawSurface* m_pBackBuffer;
  IDirectDrawSurface* m_pZBuffer;
  IDirectDrawSurface* m_pText1Surface;
  IDirectDrawSurface* m_pText2Surface;
  IDirectDrawClipper* m_pClipper;
  IDirectDrawPalette* m_pPalette;
  PALETTEENTRY m_paletteEntries[256];
  PALETTEENTRY m_originalPaletteEntries[256];
  SIZE m_text1SizeOnSurface;
  SIZE m_text2SizeOnSurface;
  HWND m_hWndMain;
  HFONT m_hFont;
  BOOL m_bIgnoreWM_SIZE;
  BOOL m_bPrimaryPalettized;
  BOOL m_bFullScreen;
  void* a_850;
  BOOL m_bOnlySystemMemory;
  BOOL m_bIsOnPrimaryDevice;
  ErrorHandler m_pErrorHandler;
  ErrorHandler m_pFatalErrorHandler;
  void* m_pErrorHandlerArg;
  void* m_pFatalErrorHandlerArg;
  int m_pauseCount;
  DeviceModesInfo* m_pCurrentDeviceModesList;
  Mode m_currentMode;

public:
  __declspec(dllexport) int FlipToGDISurface();
  __declspec(dllexport) static int GetPrimaryBitDepth();
  __declspec(dllexport) int Pause(int);

  MxDirectDraw();

  virtual ~MxDirectDraw();
  virtual BOOL Create(
    HWND hWnd,
    BOOL fullscreen_1,
    BOOL surface_fullscreen,
    BOOL onlySystemMemory,
    int width,
    int height,
    int bpp,
    const PALETTEENTRY* pPaletteEntries,
    int paletteEntryCount);
  virtual void Destroy();
  virtual void DestroyButNotDirectDraw();
  virtual const char* ErrorToString(HRESULT error);

private:
  BOOL CacheOriginalPaletteEntries();
  HRESULT CreateDDSurface(
    LPDDSURFACEDESC a2,
    LPDIRECTDRAWSURFACE* a3,
    IUnknown* a4);
  BOOL CreateTextSurfaces();
  BOOL CreateZBuffer(DWORD memorytype, DWORD depth);
  BOOL DDCreateSurfaces();
  BOOL DDInit(BOOL fullscreen);
  BOOL DDSetMode(int width, int height, int bpp);
  void Error(const char* message, int error);

  BOOL GetDDSurfaceDesc(LPDDSURFACEDESC lpDDSurfDesc, LPDIRECTDRAWSURFACE lpDDSurf);
  BOOL IsSupportedMode(int width, int height, int bpp);
  BOOL RecreateDirectDraw(GUID** a2);
  BOOL RestoreOriginalPaletteEntries();
  BOOL RestorePaletteEntries();
  BOOL RestoreSurfaces();
  BOOL SetPaletteEntries(
    const PALETTEENTRY* pPaletteEntries,
    int paletteEntryCount,
    BOOL fullscreen);
  BOOL TextToTextSurface(
    const char* text,
    IDirectDrawSurface* pSurface,
    SIZE& textSizeOnSurface);
  BOOL TextToTextSurface1(const char* text);
  BOOL TextToTextSurface2(const char* lpString);
  void unk1();
  void unk2();
};

#endif // MXDIRECTDRAW_H
