#ifndef MXDIRECT3D_H
#define MXDIRECT3D_H

#include "decomp.h"
#include "mxdirectdraw.h"
#include "mxdirectxinfo.h"
#include "mxstl/stlcompat.h"

#include <d3d.h>

// VTABLE: LEGO1 0x100db800
// VTABLE: BETA10 0x101c1af8
// SIZE 0x894
class MxDirect3D : public MxDirectDraw {
public:
	MxDirect3D();
	~MxDirect3D() override;

	BOOL Create(
		HWND hWnd,
		BOOL fullscreen_1,
		BOOL surface_fullscreen,
		BOOL onlySystemMemory,
		int width,
		int height,
		int bpp,
		const PALETTEENTRY* pPaletteEntries,
		int paletteEntryCount
	) override;                              // vtable+0x04
	void Destroy() override;                 // vtable+0x08
	void DestroyButNotDirectDraw() override; // vtable+0x0c

	MxAssignedDevice* AssignedDevice() { return m_currentDeviceInfo; }

	// FUNCTION: BETA10 0x100d8b40
	IDirect3D2* Direct3D() { return m_pDirect3d; }

	// FUNCTION: BETA10 0x100d8b70
	IDirect3DDevice2* Direct3DDevice() { return m_pDirect3dDevice; }

	BOOL SetDevice(MxDeviceEnumerate& p_deviceEnumerate, MxDriver* p_driver, Direct3DDeviceInfo* p_device);

protected:
	BOOL D3DCreate();
	BOOL D3DSetMode();

	int ZBufferDepth(MxAssignedDevice* p_assignedDevice);

	// SYNTHETIC: LEGO1 0x1009b120
	// SYNTHETIC: BETA10 0x1011c0f0
	// MxDirect3D::`scalar deleting destructor'

private:
	MxAssignedDevice* m_currentDeviceInfo; // 0x880
	IDirect3D2* m_pDirect3d;               // 0x884
	IDirect3DDevice2* m_pDirect3dDevice;   // 0x888
	BOOL m_bTexturesDisabled;              // 0x88c
	undefined4 m_unk0x890;                 // 0x890
};

// GLOBAL: LEGO1 0x100dd1b0
// GLOBAL: BETA10 0x101c2de8
// IID_IDirect3D2

#endif // MXDIRECT3D_H
