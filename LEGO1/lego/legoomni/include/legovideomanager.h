#ifndef LEGOVIDEOMANAGER_H
#define LEGOVIDEOMANAGER_H

#include "3dmanager/lego3dmanager.h"
#include "decomp.h"
#include "legounknown100d9d00.h"
#include "mxdirectx/mxdirect3d.h"
#include "mxdirectx/mxstopwatch.h"
#include "mxvideomanager.h"

#include <ddraw.h>

class LegoROI;

// VTABLE: LEGO1 0x100d9c88
// SIZE 0x590
class LegoVideoManager : public MxVideoManager {
public:
	LegoVideoManager();
	virtual ~LegoVideoManager() override;

	__declspec(dllexport) int EnableRMDevice();
	__declspec(dllexport) int DisableRMDevice();
	void EnableFullScreenMovie(MxBool p_enable);
	__declspec(dllexport) void EnableFullScreenMovie(MxBool p_enable, MxBool p_scale);
	__declspec(dllexport) void MoveCursor(MxS32 p_cursorX, MxS32 p_cursorY);

	virtual MxResult Tickle() override; // vtable+0x8
	virtual void Destroy() override;    // vtable+0x18
	virtual MxResult Create(MxVideoParam& p_videoParam, MxU32 p_frequencyMS, MxBool p_createThread)
		override;                                                                          // vtable+0x2c
	virtual MxResult RealizePalette(MxPalette*) override;                                  // vtable+0x30
	virtual void VTable0x34(MxU32 p_x, MxU32 p_y, MxU32 p_width, MxU32 p_height) override; // vtable+0x34
	virtual void VTable0x38(undefined4, undefined4);                                       // vtable+0x38
	// FUNCTION: LGEO1 0x1007ab10
	virtual LegoUnknown100d9d00* VTable0x3c() { return m_unk0x100d9d00; } // vtable+0x3c

	void SetSkyColor(float p_red, float p_green, float p_blue);
	void OverrideSkyColor(MxBool p_shouldOverride);

	inline Lego3DManager* Get3DManager() { return this->m_3dManager; }
	inline MxDirect3D* GetDirect3D() { return this->m_direct3d; }
	inline void SetRender3D(MxBool p_render3d) { this->m_render3d = p_render3d; }

private:
	MxResult CreateDirect3D();
	MxResult ConfigureD3DRM();
	void DrawFPS();

	inline void DrawCursor();

	Tgl::Renderer* m_renderer;            // 0x64
	Lego3DManager* m_3dManager;           // 0x68
	LegoROI* m_viewROI;                   // 0x6c
	undefined4 m_unk0x70;                 // 0x70
	MxDirect3D* m_direct3d;               // 0x74
	undefined4 m_unk0x78[27];             // 0x78
	MxBool m_render3d;                    // 0xe4
	MxBool m_unk0xe5;                     // 0xe5
	MxBool m_unk0xe6;                     // 0xe6
	PALETTEENTRY m_paletteEntries[256];   // 0xe7
	undefined m_padding0x4e7;             // 0x4e7
	LegoUnknown100d9d00* m_unk0x100d9d00; // 0x4e8
	MxBool m_isFullscreenMovie;           // 0x4ec
	MxPalette* m_palette;                 // 0x4f0
	MxStopWatch* m_stopWatch;             // 0x4f4
	double m_elapsedSeconds;              // 0x4f8
	MxBool m_fullScreenMovie;             // 0x500
	MxBool m_drawCursor;                  // 0x501
	MxS32 m_cursorXCopy;                  // 0x504
	MxS32 m_cursorYCopy;                  // 0x508
	MxS32 m_cursorX;                      // 0x50c
	MxS32 m_cursorY;                      // 0x510
	LPDIRECTDRAWSURFACE m_unk0x514;       // 0x514
	RECT m_unk0x518;                      // 0x518
	undefined4 m_unk0x528;                // 0x528
	MxBool m_drawFPS;                     // 0x52c
	RECT m_fpsRect;                       // 0x530
	HFONT m_arialFont;                    // 0x540
	SIZE m_fpsSize;                       // 0x544
	undefined m_pad0x54c[8];              // 0x54c
	MxBool m_unk0x554;                    // 0x554
	MxBool m_paused;                      // 0x555
	undefined m_pad0x556[0x39];           // 0x556
};

// SYNTHETIC: LEGO1 0x1007ab20
// LegoVideoManager::`scalar deleting destructor'

#endif // LEGOVIDEOMANAGER_H
