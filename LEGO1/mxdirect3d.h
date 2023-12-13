#ifndef MXDIRECT3D_H
#define MXDIRECT3D_H

#include "decomp.h"
#include "mxdirectdraw.h"
#include "mxtypes.h"

#include <d3d.h>

// SIZE 0xe4
class MxDeviceModeFinder {
public:
	MxDeviceModeFinder();
	~MxDeviceModeFinder();

	undefined4 m_pad[56];
	MxDirectDraw::DeviceModesInfo* m_deviceInfo; // +0xe0
};

// VTABLE: LEGO1 0x100db814
// or is it 0x100d9cc8?
// SIZE 0x198
class MxDeviceEnumerate {
public:
	MxDeviceEnumerate();
	virtual MxResult DoEnumerate();

	BOOL FUN_1009c070();

	const char* EnumerateErrorToString(HRESULT p_error);

	undefined4 m_unk0x004;
	undefined4 m_unk0x008;
	undefined4 m_unk0x00c;
	MxBool m_unk0x010; // +0x10

	undefined4 m_unk0x014[97];
};

// VTABLE: LEGO1 0x100db800
// SIZE 0x894
class MxDirect3D : public MxDirectDraw {
public:
	MxDirect3D();

	void Clear();
	inline MxDeviceModeFinder* GetDeviceModeFinder() { return this->m_pDeviceModeFinder; };

	virtual ~MxDirect3D();
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
	);
	virtual void Destroy();

	BOOL CreateIDirect3D();
	BOOL D3DSetMode();

	static void BuildErrorString(const char*, ...);

private:
	MxDeviceModeFinder* m_pDeviceModeFinder; // +0x880
	IDirect3D* m_pDirect3d;                  // +0x884
	IDirect3DDevice* m_pDirect3dDevice;
	undefined4 m_unk0x88c;
	undefined4 m_unk0x890;
};

BOOL FAR PASCAL EnumerateCallback(GUID FAR*, LPSTR, LPSTR, LPVOID);

#endif // MXDIRECT3D_H
