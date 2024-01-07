#ifndef MXDIRECTDRAW_H
#define MXDIRECTDRAW_H

#include <ddraw.h>
#include <windows.h>

// VTABLE: LEGO1 0x100db818
// SIZE 0x880
class MxDirectDraw {
public:
	typedef void (*ErrorHandler)(const char*, HRESULT, void*);

	// SIZE 0x0c
	struct Mode {
		int operator==(const Mode& p_mode) const
		{
			return ((width == p_mode.width) && (height == p_mode.height) && (bitsPerPixel == p_mode.bitsPerPixel));
		}

		int width;        // 0x00
		int height;       // 0x04
		int bitsPerPixel; // 0x08
	};

	// SIZE 0x17c
	struct DeviceModesInfo {
		DeviceModesInfo();
		~DeviceModesInfo();

		GUID* m_guid;      // 0x00
		Mode* m_modeArray; // 0x04
		int m_count;       // 0x08
		DDCAPS m_ddcaps;   // 0x0c
		void* m_unk0x178;  // 0x178
	};

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

	BOOL CacheOriginalPaletteEntries();
	HRESULT CreateDDSurface(LPDDSURFACEDESC a2, LPDIRECTDRAWSURFACE* a3, IUnknown* a4);
	BOOL CreateTextSurfaces();
	BOOL CreateZBuffer(DWORD memorytype, DWORD depth);
	BOOL DDCreateSurfaces();
	BOOL DDInit(BOOL fullscreen);
	BOOL DDSetMode(int width, int height, int bpp);
	void Error(const char* p_message, int p_error);

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

	inline IDirectDraw* GetDirectDraw() { return m_pDirectDraw; }
	inline IDirectDrawSurface* GetFrontBuffer() { return m_pFrontBuffer; }
	inline IDirectDrawSurface* GetBackBuffer() { return m_pBackBuffer; }
	inline IDirectDrawClipper* GetClipper() { return m_pClipper; }

protected:
	BOOL m_bOnlySoftRender;                     // 0x04
	BOOL m_bFlipSurfaces;                       // 0x08
	IDirectDraw* m_pDirectDraw;                 // 0x0c
	IDirectDrawSurface* m_pFrontBuffer;         // 0x10
	IDirectDrawSurface* m_pBackBuffer;          // 0x14
	IDirectDrawSurface* m_pZBuffer;             // 0x18
	IDirectDrawSurface* m_pText1Surface;        // 0x1c
	IDirectDrawSurface* m_pText2Surface;        // 0x20
	IDirectDrawClipper* m_pClipper;             // 0x24
	IDirectDrawPalette* m_pPalette;             // 0x28
	PALETTEENTRY m_paletteEntries[256];         // 0x2c
	PALETTEENTRY m_originalPaletteEntries[256]; // 0x42c
	SIZE m_text1SizeOnSurface;                  // 0x82c
	SIZE m_text2SizeOnSurface;                  // 0x834
	HWND m_hWndMain;                            // 0x83c
	HFONT m_hFont;                              // 0x840
	BOOL m_bIgnoreWMSIZE;                       // 0x844
	BOOL m_bPrimaryPalettized;                  // 0x848
	BOOL m_bFullScreen;                         // 0x84c
	void* m_unk0x850;                           // 0x850
	BOOL m_bOnlySystemMemory;                   // 0x854
	BOOL m_bIsOnPrimaryDevice;                  // 0x858
	ErrorHandler m_pErrorHandler;               // 0x85c
	ErrorHandler m_pFatalErrorHandler;          // 0x860
	void* m_pErrorHandlerArg;                   // 0x864
	void* m_pFatalErrorHandlerArg;              // 0x868
	int m_pauseCount;                           // 0x86c
	DeviceModesInfo* m_pCurrentDeviceModesList; // 0x870
	Mode m_currentMode;                         // 0x874
};

#endif // MXDIRECTDRAW_H
