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
struct MxDriver;
struct MxDevice;

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
	BOOL FUN_1009b5f0(MxDeviceEnumerate& p_deviceEnumerator, MxDriver* p_driver, MxDevice* p_device);

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

// SIZE 0x1a4
struct MxDevice {
	MxDevice() {}
	~MxDevice();
	MxDevice(
		LPGUID p_guid,
		LPSTR p_deviceDesc,
		LPSTR p_deviceName,
		LPD3DDEVICEDESC p_HWDesc,
		LPD3DDEVICEDESC p_HELDesc
	);

	void Init(
		LPGUID p_guid,
		LPSTR p_deviceDesc,
		LPSTR p_deviceName,
		LPD3DDEVICEDESC p_HWDesc,
		LPD3DDEVICEDESC p_HELDesc
	);

	LPGUID m_guid;           // 0x00
	char* m_deviceDesc;      // 0x04
	char* m_deviceName;      // 0x08
	D3DDEVICEDESC m_HWDesc;  // 0x0c
	D3DDEVICEDESC m_HELDesc; // 0xd8

	MxBool operator==(MxDevice) const { return TRUE; }
	MxBool operator<(MxDevice) const { return TRUE; }
};

// SIZE 0x0c
struct MxDisplayMode {
	DWORD m_width;        // 0x00
	DWORD m_height;       // 0x04
	DWORD m_bitsPerPixel; // 0x08

	MxBool operator==(MxDisplayMode) const { return TRUE; }
	MxBool operator<(MxDisplayMode) const { return TRUE; }
};

// SIZE 0x190
struct MxDriver {
	MxDriver() {}
	~MxDriver();
	MxDriver(LPGUID p_guid, LPSTR p_driverDesc, LPSTR p_driverName);

	void Init(LPGUID p_guid, LPSTR p_driverDesc, LPSTR p_driverName);

	LPGUID m_guid;                      // 0x00
	char* m_driverDesc;                 // 0x04
	char* m_driverName;                 // 0x08
	DDCAPS m_ddCaps;                    // 0x0c
	list<MxDevice> m_devices;           // 0x178
	list<MxDisplayMode> m_displayModes; // 0x184

	MxBool operator==(MxDriver) const { return TRUE; }
	MxBool operator<(MxDriver) const { return TRUE; }
};

// clang-format off
// TEMPLATE: LEGO1 0x1009b900
// list<MxDevice,allocator<MxDevice> >::~list<MxDevice,allocator<MxDevice> >
// clang-format on

// clang-format off
// TEMPLATE: LEGO1 0x1009b970
// list<MxDisplayMode,allocator<MxDisplayMode> >::~list<MxDisplayMode,allocator<MxDisplayMode> >
// clang-format on

// TEMPLATE: LEGO1 0x1009b9e0
// List<MxDevice>::~List<MxDevice>

// TEMPLATE: LEGO1 0x1009ba30
// List<MxDisplayMode>::~List<MxDisplayMode>

// clang-format off
// TEMPLATE: LEGO1 0x1009bf50
// list<MxDriver,allocator<MxDriver> >::~list<MxDriver,allocator<MxDriver> >
// clang-format on

// TEMPLATE: LEGO1 0x1009bfc0
// List<MxDriver>::~List<MxDriver>

// Compiler-generated copy ctor
// Part of this function are two more synthetic sub-routines,
// LEGO1 0x1009c400 and LEGO1 0x1009c460
// SYNTHETIC: LEGO1 0x1009c290
// MxDriver::MxDriver

// SYNTHETIC: LEGO1 0x1009d450
// MxDriver::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1009d470
// MxDevice::`scalar deleting destructor'

// VTABLE: LEGO1 0x100db814
// SIZE 0x14
class MxDeviceEnumerate {
public:
	MxDeviceEnumerate();
	// FUNCTION: LEGO1 0x1009c010
	~MxDeviceEnumerate() {}

	virtual MxResult DoEnumerate(); // vtable+0x00

	BOOL EnumDirectDrawCallback(LPGUID p_guid, LPSTR p_driverDesc, LPSTR p_driverName);
	HRESULT EnumDisplayModesCallback(LPDDSURFACEDESC p_ddsd);
	HRESULT EnumDevicesCallback(
		LPGUID p_guid,
		LPSTR p_deviceDesc,
		LPSTR p_deviceName,
		LPD3DDEVICEDESC p_HWDesc,
		LPD3DDEVICEDESC p_HELDesc
	);
	const char* EnumerateErrorToString(HRESULT p_error);
	MxS32 ParseDeviceName(const char* p_deviceId);
	MxS32 ProcessDeviceBytes(MxS32 p_deviceNum, GUID& p_guid);
	MxResult GetDevice(MxS32 p_deviceNum, MxDriver*& p_driver, MxDevice*& p_device);
	MxS32 FUN_1009d0d0();
	MxResult FUN_1009d210();
	MxBool FUN_1009d370(MxDriver& p_driver);
	MxBool FUN_1009d3d0(MxDevice& p_device);

	static void BuildErrorString(const char*, ...);
	static BOOL CALLBACK
	DirectDrawEnumerateCallback(LPGUID p_guid, LPSTR p_driverDesc, LPSTR p_driverName, LPVOID p_context);
	static HRESULT CALLBACK DisplayModesEnumerateCallback(LPDDSURFACEDESC p_ddsd, LPVOID p_context);
	static HRESULT CALLBACK DevicesEnumerateCallback(
		LPGUID p_guid,
		LPSTR p_deviceDesc,
		LPSTR p_deviceName,
		LPD3DDEVICEDESC p_HWDesc,
		LPD3DDEVICEDESC p_HELDesc,
		LPVOID p_context
	);
	static undefined4 FUN_1009d1a0();
	static undefined4 FUN_1009d1e0();

private:
	list<MxDriver> m_list; // 0x04
	MxBool m_initialized;  // 0x10
};

// VTABLE: LEGO1 0x100d9cc8
// SIZE 0x14
class MxDeviceEnumerate100d9cc8 : public MxDeviceEnumerate {};

#endif // MXDIRECT3D_H
