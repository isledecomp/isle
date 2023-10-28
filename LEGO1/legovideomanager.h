#ifndef LEGOVIDEOMANAGER_H
#define LEGOVIDEOMANAGER_H

#include "decomp.h"
#include "lego3dmanager.h"
#include "mxdirect3d.h"
#include "mxvideomanager.h"

#include <ddraw.h>

// VTABLE 0x100d9c88
// SIZE 0x590
class LegoVideoManager : public MxVideoManager {
public:
	LegoVideoManager();
	virtual ~LegoVideoManager() override;

	__declspec(dllexport) int EnableRMDevice();
	__declspec(dllexport) int DisableRMDevice();
	void EnableFullScreenMovie(MxBool p_enable);
	__declspec(dllexport) void EnableFullScreenMovie(MxBool p_enable, MxBool p_scale);
	__declspec(dllexport) void MoveCursor(int x, int y);

	inline Lego3DManager* Get3DManager() { return this->m_3dManager; }
	inline MxDirect3D* GetDirect3D() { return this->m_direct3d; }

	void SetSkyColor(float r, float g, float b);
	inline void SetUnkE4(MxBool p_unk0xe4) { this->m_unk0xe4 = p_unk0xe4; }

	// OFFSET: LEGO1 0x1007c4c0
	void OverrideSkyColor(MxBool p_shouldOverride)
	{
		this->m_videoParam.GetPalette()->SetOverrideSkyColor(p_shouldOverride);
	}

private:
	undefined4 m_unk64;
	Lego3DManager* m_3dManager;
	undefined4 m_unk6c;
	undefined4 m_unk70;
	MxDirect3D* m_direct3d;
	undefined m_pad0x78[0x6c];
	MxBool m_unk0xe4;
	undefined m_pad0xe8[0x41c];
	MxBool m_cursorMoved; // 0x501
	undefined m_pad0x502[0x8];
	MxS32 m_cursorX; // 0x50c
	MxS32 m_cursorY; // 0x510
	undefined m_pad0x514[0x7c];
};

#endif // LEGOVIDEOMANAGER_H
