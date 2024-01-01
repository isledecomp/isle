#ifndef MXDIRECTDRAW_H
#define MXDIRECTDRAW_H

#include "mxtypes.h"

#include <ddraw.h>
#include <windows.h>

// VTABLE: LEGO1 0x100db818
// SIZE 0x880
class MxDirectDraw {
public:
	typedef void (*ErrorHandler)(const char*, HRESULT, void*);

	// size 0x0c
	struct Mode {
		MxS32 m_width;
		MxS32 m_height;
		MxS32 m_bitsPerPixel;

		MxS32 operator==(const Mode& p_mode) const
		{
			return (
				(m_width == p_mode.m_width) && (m_height == p_mode.m_height) &&
				(m_bitsPerPixel == p_mode.m_bitsPerPixel)
			);
		}
	};

	// SIZE 0x17c
	struct DeviceModesInfo {
		GUID* m_guid;
		Mode* m_modeArray;
		MxS32 m_count;
		DDCAPS m_ddcaps;
		void* m_unk0x178;

		DeviceModesInfo();
		~DeviceModesInfo();
	};

protected:
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
	BOOL m_bIgnoreWMSIZE;
	BOOL m_bPrimaryPalettized;
	BOOL m_bFullScreen;
	void* m_unk0x850;
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
		int paletteEntryCount
	);                                                  // vtable+0x04
	virtual void Destroy();                             // vtable+0x08
	virtual void DestroyButNotDirectDraw();             // vtable+0x0c
	virtual const char* ErrorToString(HRESULT p_error); // vtable+0x10

	inline IDirectDraw* GetDirectDraw() { return m_pDirectDraw; }
	inline IDirectDrawSurface* GetFrontBuffer() { return m_pFrontBuffer; }
	inline IDirectDrawSurface* GetBackBuffer() { return m_pBackBuffer; }
	inline IDirectDrawClipper* GetClipper() { return m_pClipper; }

protected:
	BOOL CacheOriginalPaletteEntries();
	HRESULT CreateDDSurface(LPDDSURFACEDESC a2, LPDIRECTDRAWSURFACE* a3, IUnknown* a4);
	BOOL CreateTextSurfaces();
	BOOL CreateZBuffer(DWORD memorytype, DWORD depth);
	BOOL DDCreateSurfaces();
	BOOL DDInit(BOOL fullscreen);
	BOOL DDSetMode(int width, int height, int bpp);
	void Error(const char* p_message, MxS32 p_error);

	BOOL GetDDSurfaceDesc(LPDDSURFACEDESC lpDDSurfDesc, LPDIRECTDRAWSURFACE lpDDSurf);
	BOOL IsSupportedMode(int width, int height, int bpp);
	BOOL RecreateDirectDraw(GUID** a2);
	BOOL RestoreOriginalPaletteEntries();
	BOOL RestorePaletteEntries();
	BOOL RestoreSurfaces();
	BOOL SetPaletteEntries(const PALETTEENTRY* pPaletteEntries, int paletteEntryCount, BOOL fullscreen);
	BOOL TextToTextSurface(const char* text, IDirectDrawSurface* pSurface, SIZE& textSizeOnSurface);
	BOOL TextToTextSurface1(const char* text);
	BOOL TextToTextSurface2(const char* lpString);
	void FUN_1009e020();
	void FUN_1009d920();
};

#endif // MXDIRECTDRAW_H
