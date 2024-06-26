#ifndef MXDIRECTXINFO_H
#define MXDIRECTXINFO_H

#include "decomp.h"
#include "mxstl/stlcompat.h"

#include <d3d.h>

// SIZE 0x17c
struct DeviceModesInfo {
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

	DeviceModesInfo();
	~DeviceModesInfo();

	GUID* m_guid;      // 0x00
	Mode* m_modeArray; // 0x04
	int m_count;       // 0x08
	DDCAPS m_ddcaps;   // 0x0c
	void* m_unk0x178;  // 0x178

	// SYNTHETIC: BETA10 0x1011c650
	// MxDirectDraw::DeviceModesInfo::`scalar deleting destructor'
};

// SIZE 0xe4
class MxAssignedDevice {
public:
	enum {
		c_hardwareMode = 0x01,
		c_primaryDevice = 0x02
	};

	MxAssignedDevice();
	~MxAssignedDevice();

	inline unsigned int GetFlags() { return m_flags; }
	inline BOOL GetHardwareMode() { return ((int) m_flags << 31) >> 31; }
	inline D3DDEVICEDESC& GetDesc() { return m_desc; }

	friend class MxDirect3D;

	// SYNTHETIC: BETA10 0x1011c130
	// MxAssignedDevice::`scalar deleting destructor'

private:
	GUID m_guid;                   // 0x00
	unsigned int m_flags;          // 0x10
	D3DDEVICEDESC m_desc;          // 0x14
	DeviceModesInfo* m_deviceInfo; // 0xe0
};

// SIZE 0x1a4
struct Direct3DDeviceInfo {
	Direct3DDeviceInfo() {}
	~Direct3DDeviceInfo();
	Direct3DDeviceInfo(
		LPGUID p_guid,
		LPSTR p_deviceDesc,
		LPSTR p_deviceName,
		LPD3DDEVICEDESC p_HWDesc,
		LPD3DDEVICEDESC p_HELDesc
	);

	void Initialize(
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

	int operator==(Direct3DDeviceInfo) const { return 0; }
	int operator<(Direct3DDeviceInfo) const { return 0; }
};

// SIZE 0x0c
struct MxDisplayMode {
	DWORD m_width;        // 0x00
	DWORD m_height;       // 0x04
	DWORD m_bitsPerPixel; // 0x08

	int operator==(MxDisplayMode) const { return 0; }
	int operator<(MxDisplayMode) const { return 0; }
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
	list<Direct3DDeviceInfo> m_devices; // 0x178
	list<MxDisplayMode> m_displayModes; // 0x184

	int operator==(MxDriver) const { return 0; }
	int operator<(MxDriver) const { return 0; }
};

// clang-format off
// TEMPLATE: CONFIG 0x401000
// TEMPLATE: LEGO1 0x1009b900
// list<Direct3DDeviceInfo,allocator<Direct3DDeviceInfo> >::~list<Direct3DDeviceInfo,allocator<Direct3DDeviceInfo> >
// clang-format on

// clang-format off
// TEMPLATE: CONFIG 0x401070
// TEMPLATE: LEGO1 0x1009b970
// list<MxDisplayMode,allocator<MxDisplayMode> >::~list<MxDisplayMode,allocator<MxDisplayMode> >
// clang-format on

// TEMPLATE: CONFIG 0x4010e0
// TEMPLATE: LEGO1 0x1009b9e0
// TEMPLATE: BETA10 0x1011f3d0
// List<Direct3DDeviceInfo>::~List<Direct3DDeviceInfo>

// TEMPLATE: CONFIG 0x401130
// TEMPLATE: LEGO1 0x1009ba30
// TEMPLATE: BETA10 0x1011f430
// List<MxDisplayMode>::~List<MxDisplayMode>

// clang-format off
// TEMPLATE: CONFIG 0x401650
// TEMPLATE: LEGO1 0x1009bf50
// list<MxDriver,allocator<MxDriver> >::~list<MxDriver,allocator<MxDriver> >
// clang-format on

// TEMPLATE: CONFIG 0x4016c0
// TEMPLATE: LEGO1 0x1009bfc0
// TEMPLATE: BETA10 0x1011f6f0
// List<MxDriver>::~List<MxDriver>

// Compiler-generated copy ctor
// SYNTHETIC: CONFIG 0x401990
// SYNTHETIC: LEGO1 0x1009c290
// MxDriver::MxDriver

// SYNTHETIC: CONFIG 0x401b00
// SYNTHETIC: LEGO1 0x1009c400
// list<Direct3DDeviceInfo,allocator<Direct3DDeviceInfo> >::insert

// SYNTHETIC: CONFIG 0x401b60
// SYNTHETIC: LEGO1 0x1009c460
// list<MxDisplayMode,allocator<MxDisplayMode> >::insert

// SYNTHETIC: LEGO1 0x1009d450
// MxDriver::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1009d470
// Direct3DDeviceInfo::`scalar deleting destructor'

// VTABLE: CONFIG 0x00406000
// VTABLE: LEGO1 0x100db814
// VTABLE: BETA10 0x101c1b0c
// SIZE 0x14
class MxDeviceEnumerate {
public:
	MxDeviceEnumerate();
	~MxDeviceEnumerate();

	virtual int DoEnumerate(); // vtable+0x00

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
	int ParseDeviceName(const char* p_deviceId);
	int ProcessDeviceBytes(int p_deviceNum, GUID& p_guid);
	int GetDevice(int p_deviceNum, MxDriver*& p_driver, Direct3DDeviceInfo*& p_device);

#if defined(MXDIRECTX_FOR_CONFIG) || defined(_DEBUG)
	int FormatDeviceName(char* p_buffer, const MxDriver* p_driver, const Direct3DDeviceInfo* p_device) const;
#endif

	int FUN_1009d0d0();
	int FUN_1009d210();
	unsigned char DriverSupportsRequiredDisplayMode(MxDriver& p_driver);
	unsigned char FUN_1009d3d0(Direct3DDeviceInfo& p_device);

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
	static int SupportsMMX();
	static int SupportsCPUID();

	friend class MxDirect3D;

	const list<MxDriver>& GetDriverList() const { return m_list; }

	// FUNCTION: BETA10 0x1011d320
	unsigned char IsInitialized() const { return m_initialized; }

private:
	list<MxDriver> m_list;       // 0x04
	unsigned char m_initialized; // 0x10
};

// VTABLE: LEGO1 0x100d9cc8
// VTABLE: BETA10 0x101befb4
// SIZE 0x14
class MxDeviceEnumerate100d9cc8 : public MxDeviceEnumerate {};

// SYNTHETIC: BETA10 0x100d8d10
// MxDeviceEnumerate100d9cc8::MxDeviceEnumerate100d9cc8

// SYNTHETIC: LEGO1 0x1007b590
// SYNTHETIC: BETA10 0x100d8da0
// MxDeviceEnumerate100d9cc8::~MxDeviceEnumerate100d9cc8

#endif // MXDIRECTXINFO_H
