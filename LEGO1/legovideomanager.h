#ifndef LEGOVIDEOMANAGER_H
#define LEGOVIDEOMANAGER_H

#include "decomp.h"
#include "lego3dmanager.h"
#include "mxdirect3d.h"
#include "mxdirectx/mxstopwatch.h"
#include "mxunknown100d9d00.h"
#include "mxvideomanager.h"

#include <ddraw.h>

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
	virtual MxUnknown100d9d00* VTable0x3c() { return m_unk0x100d9d00; } // vtable+0x3c

	void SetSkyColor(float p_red, float p_green, float p_blue);
	void OverrideSkyColor(MxBool p_shouldOverride);

	inline Lego3DManager* Get3DManager() { return this->m_3dManager; }
	inline MxDirect3D* GetDirect3D() { return this->m_direct3d; }
	inline void SetUnkE4(MxBool p_unk0xe4) { this->m_unk0xe4 = p_unk0xe4; }

private:
	MxResult CreateDirect3D();
	MxResult FUN_1007c930();

	Tgl::Renderer* m_renderer;
	Lego3DManager* m_3dManager; // 0x68
	LegoROI* m_viewROI;         // 0x6c
	undefined4 m_unk0x70;
	MxDirect3D* m_direct3d; // 0x74
	undefined4 m_unk0x78[27];
	MxBool m_unk0xe4;
	MxBool m_unk0xe5;
	MxBool m_unk0xe6;
	PALETTEENTRY m_paletteEntries[256]; // 0xe7
	undefined m_padding0x4e7;
	MxUnknown100d9d00* m_unk0x100d9d00; // 0x4e8
	MxBool m_isFullscreenMovie;         // 0x4ec
	MxPalette* m_palette;               // 0x4f0
	MxStopWatch* m_stopWatch;           // 0x4f4
	undefined m_padding0x4f4[8];
	MxBool m_unk0x500;
	MxBool m_cursorMoved; // 0x501
	MxS32 m_cursorXCopy;  // 0x504
	MxS32 m_cursorYCopy;  // 0x508
	MxS32 m_cursorX;      // 0x50c
	MxS32 m_cursorY;      // 0x510
	undefined4 m_unk0x514;
	undefined m_pad0x518[0x10];
	undefined4 m_unk0x528;
	MxBool m_drawFPS;  // 0x52c
	RECT m_fpsRect;    // 0x530
	HFONT m_arialFont; // 0x540
	SIZE m_fpsSize;    // 0x544
	undefined m_pad0x54c[8];
	undefined m_unk0x554;
	MxBool m_initialized; // 0x555
	undefined m_pad0x556[0x39];
};

#endif // LEGOVIDEOMANAGER_H
