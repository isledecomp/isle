#ifndef LEGOVIDEOMANAGER_H
#define LEGOVIDEOMANAGER_H

#include "decomp.h"
#include "legophonemelist.h"
#include "mxvideomanager.h"

#include <d3drm.h>
#include <ddraw.h>

class Lego3DManager;
class LegoROI;
class MxDirect3D;
class MxStopWatch;
struct ViewportAppData;

namespace Tgl
{
class Renderer;
}

// VTABLE: LEGO1 0x100d9c88
// SIZE 0x590
class LegoVideoManager : public MxVideoManager {
public:
	LegoVideoManager();
	~LegoVideoManager() override;

	int EnableRMDevice();
	int DisableRMDevice();
	void EnableFullScreenMovie(MxBool p_enable);
	void EnableFullScreenMovie(MxBool p_enable, MxBool p_scale);
	void MoveCursor(MxS32 p_cursorX, MxS32 p_cursorY);
	void ToggleFPS(MxBool p_visible);

	MxResult Tickle() override;                                                                       // vtable+0x08
	void Destroy() override;                                                                          // vtable+0x18
	MxResult Create(MxVideoParam& p_videoParam, MxU32 p_frequencyMS, MxBool p_createThread) override; // vtable+0x2c
	MxResult RealizePalette(MxPalette*) override;                                                     // vtable+0x30
	void UpdateView(MxU32 p_x, MxU32 p_y, MxU32 p_width, MxU32 p_height) override;                    // vtable+0x34
	virtual MxPresenter* GetPresenterAt(MxS32 p_x, MxS32 p_y);                                        // vtable+0x38

	// FUNCTION: LEGO1 0x1007ab10
	virtual LegoPhonemeList* GetPhonemeList() { return m_phonemeRefList; } // vtable+0x3c

	void SetSkyColor(float p_red, float p_green, float p_blue);
	void OverrideSkyColor(MxBool p_shouldOverride);
	MxResult ResetPalette(MxBool p_ignoreSkyColor);
	MxPresenter* GetPresenterByActionObjectName(const char* p_char);

	void FUN_1007c520();

	Tgl::Renderer* GetRenderer() { return m_renderer; }

	// FUNCTION: BETA10 0x100117e0
	Lego3DManager* Get3DManager() { return m_3dManager; }

	// FUNCTION: BETA10 0x1003a380
	LegoROI* GetViewROI() { return m_viewROI; }

	MxDirect3D* GetDirect3D() { return m_direct3d; }
	MxBool GetRender3D() { return m_render3d; }
	double GetElapsedSeconds() { return m_elapsedSeconds; }

	void SetRender3D(MxBool p_render3d) { m_render3d = p_render3d; }
	void SetUnk0x554(MxBool p_unk0x554) { m_unk0x554 = p_unk0x554; }

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
	LegoPhonemeList* m_phonemeRefList;    // 0x4e8
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
	LPDIRECTDRAWSURFACE m_cursorSurface;  // 0x514
	RECT m_cursorRect;                    // 0x518
	LPDIRECTDRAWSURFACE m_unk0x528;       // 0x528
	MxBool m_drawFPS;                     // 0x52c
	RECT m_fpsRect;                       // 0x530
	HFONT m_arialFont;                    // 0x540
	SIZE m_fpsSize;                       // 0x544
	MxFloat m_unk0x54c;                   // 0x54c
	MxFloat m_unk0x550;                   // 0x550
	MxBool m_unk0x554;                    // 0x554
	MxBool m_paused;                      // 0x555
	D3DVALUE m_back;                      // 0x558
	D3DVALUE m_front;                     // 0x55c
	float m_cameraWidth;                  // 0x560
	float m_cameraHeight;                 // 0x564
	D3DVALUE m_fov;                       // 0x55c
	IDirect3DRMFrame* m_camera;           // 0x56c
	D3DRMPROJECTIONTYPE m_projection;     // 0x570
	ViewportAppData* m_appdata;           // 0x574
	D3DRMRENDERQUALITY m_quality;         // 0x578
	DWORD m_shades;                       // 0x57c
	D3DRMTEXTUREQUALITY m_textureQuality; // 0x580
	DWORD m_rendermode;                   // 0x584
	BOOL m_dither;                        // 0x588
	DWORD m_bufferCount;                  // 0x58c
};

// SYNTHETIC: LEGO1 0x1007ab20
// LegoVideoManager::`scalar deleting destructor'

#endif // LEGOVIDEOMANAGER_H
