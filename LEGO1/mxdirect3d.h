#ifndef MXDIRECT3D_H
#define MXDIRECT3D_H

#include "decomp.h"
#include "mxdirectdraw.h"
#include "mxstl/stlcompat.h"
#include "mxtypes.h"

#include <d3d.h>

// SIZE 0xe4
class MxDeviceModeFinder {
public:
	MxDeviceModeFinder();
	~MxDeviceModeFinder();

	undefined m_pad[0xe0];                       // 0x00
	MxDirectDraw::DeviceModesInfo* m_deviceInfo; // 0xe0
};

class MxDeviceEnumerate;

// VTABLE: LEGO1 0x100db800
// SIZE 0x894
class MxDirect3D : public MxDirectDraw {
public:
	MxDirect3D();
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
	) override;                                      // vtable+0x04
	virtual void Destroy() override;                 // vtable+0x08
	virtual void DestroyButNotDirectDraw() override; // vtable+0x0c

	BOOL CreateIDirect3D();
	BOOL D3DSetMode();
	BOOL FUN_1009b5f0(MxDeviceEnumerate& p_deviceEnumerate, undefined* p_und1, undefined* p_und2);

	inline MxDeviceModeFinder* GetDeviceModeFinder() { return this->m_pDeviceModeFinder; };
	inline IDirect3D* GetDirect3D() { return this->m_pDirect3d; }
	inline IDirect3DDevice* GetDirect3DDevice() { return this->m_pDirect3dDevice; }

private:
	MxDeviceModeFinder* m_pDeviceModeFinder; // 0x880
	IDirect3D* m_pDirect3d;                  // 0x884
	IDirect3DDevice* m_pDirect3dDevice;      // 0x888
	undefined4 m_unk0x88c;                   // 0x88c
	undefined4 m_unk0x890;                   // 0x890
};

// SIZE 0x190
struct MxDeviceEnumerateElement {
	undefined m_pad[0x190]; // 0x00

	MxBool operator==(MxDeviceEnumerateElement) const { return TRUE; }
	MxBool operator<(MxDeviceEnumerateElement) const { return TRUE; }
};

// VTABLE: LEGO1 0x100db814
// SIZE 0x14
class MxDeviceEnumerate {
public:
	MxDeviceEnumerate();

	virtual MxResult DoEnumerate(); // vtable+0x00

	BOOL EnumDirectDrawCallback(GUID FAR* p_guid, LPSTR p_driverName, LPSTR p_driverDesc);
	const char* EnumerateErrorToString(HRESULT p_error);
	MxS32 ParseDeviceName(const char* p_deviceId);
	MxResult FUN_1009d030(MxS32 p_und1, undefined** p_und2, undefined** p_und3);
	MxResult FUN_1009d0d0();
	MxResult FUN_1009d210();

	static void BuildErrorString(const char*, ...);

	list<MxDeviceEnumerateElement> m_list; // 0x04
	MxBool m_unk0x10;                      // 0x10
};

BOOL CALLBACK EnumerateCallback(GUID FAR*, LPSTR, LPSTR, LPVOID);

// VTABLE: LEGO1 0x100d9cc8
// SIZE 0x14
class MxDeviceEnumerate100d9cc8 : public MxDeviceEnumerate {};

#endif // MXDIRECT3D_H
