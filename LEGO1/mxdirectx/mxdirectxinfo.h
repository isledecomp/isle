#ifndef MXDIRECTXINFO_H
#define MXDIRECTXINFO_H

#include "decomp.h"
#include "mxstl/stlcompat.h"

#include <d3d.h>

// SIZE 0x17c
struct DeviceModesInfo {
	// SIZE 0x0c
	struct Mode {
		// FUNCTION: BETA10 0x10122fc0
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
	// DeviceModesInfo::`scalar deleting destructor'
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

	unsigned int GetFlags() { return m_flags; }
	BOOL GetHardwareMode() { return ((int) m_flags << 31) >> 31; }
	D3DDEVICEDESC& GetDesc() { return m_desc; }

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
	MxDisplayMode() {}
	// FUNCTION: BETA10 0x1011f920
	MxDisplayMode(DWORD p_width, DWORD p_height, DWORD p_bitsPerPixel)
	{
		m_width = p_width;
		m_height = p_height;
		m_bitsPerPixel = p_bitsPerPixel;
	}

	int operator==(MxDisplayMode) const { return 0; }
	int operator<(MxDisplayMode) const { return 0; }

	DWORD m_width;        // 0x00
	DWORD m_height;       // 0x04
	DWORD m_bitsPerPixel; // 0x08
};

// SIZE 0x190
struct MxDriver {
	MxDriver() {}
	~MxDriver();
	MxDriver(LPGUID p_guid);
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

// TEMPLATE: CONFIG 0x401000
// TEMPLATE: LEGO1 0x1009b900
// TEMPLATE: BETA10 0x1011ee40
// list<Direct3DDeviceInfo,allocator<Direct3DDeviceInfo> >::~list<Direct3DDeviceInfo,allocator<Direct3DDeviceInfo> >

// TEMPLATE: CONFIG 0x401070
// TEMPLATE: LEGO1 0x1009b970
// TEMPLATE: BETA10 0x1011f0a0
// list<MxDisplayMode,allocator<MxDisplayMode> >::~list<MxDisplayMode,allocator<MxDisplayMode> >

// TEMPLATE: CONFIG 0x4010e0
// TEMPLATE: LEGO1 0x1009b9e0
// TEMPLATE: BETA10 0x1011f3d0
// List<Direct3DDeviceInfo>::~List<Direct3DDeviceInfo>

// TEMPLATE: CONFIG 0x401130
// TEMPLATE: LEGO1 0x1009ba30
// TEMPLATE: BETA10 0x1011f430
// List<MxDisplayMode>::~List<MxDisplayMode>

// TEMPLATE: CONFIG 0x401650
// TEMPLATE: LEGO1 0x1009bf50
// TEMPLATE: BETA10 0x1011f550
// list<MxDriver,allocator<MxDriver> >::~list<MxDriver,allocator<MxDriver> >

// TEMPLATE: CONFIG 0x4016c0
// TEMPLATE: LEGO1 0x1009bfc0
// TEMPLATE: BETA10 0x1011f6f0
// List<MxDriver>::~List<MxDriver>

// Compiler-generated copy ctor for MxDriver
// SYNTHETIC: CONFIG 0x401990
// SYNTHETIC: LEGO1 0x1009c290
// ??0MxDriver@@QAE@ABU0@@Z

// TEMPLATE: CONFIG 0x401b00
// TEMPLATE: LEGO1 0x1009c400
// TEMPLATE: BETA10 0x1011fad0
// list<Direct3DDeviceInfo,allocator<Direct3DDeviceInfo> >::insert

// TEMPLATE: CONFIG 0x401b60
// TEMPLATE: LEGO1 0x1009c460
// TEMPLATE: BETA10 0x1011f9a0
// list<MxDisplayMode,allocator<MxDisplayMode> >::insert

// SYNTHETIC: CONFIG 0x402be0
// SYNTHETIC: LEGO1 0x1009d450
// MxDriver::`scalar deleting destructor'

// SYNTHETIC: CONFIG 0x402c00
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

	friend class MxDirect3D;

	const list<MxDriver>& GetDriverList() const { return m_list; }

	// SIZE 0x10
	struct GUID4 {
		int m_data1;
		int m_data2;
		int m_data3;
		int m_data4;

		// FUNCTION: BETA10 0x1011d340
		static unsigned char Compare(const GUID4& p_a, const GUID4& p_b)
		{
			return p_a.m_data1 == p_b.m_data1 && p_a.m_data2 == p_b.m_data2 && p_a.m_data3 == p_b.m_data3 &&
				   p_a.m_data4 == p_b.m_data4;
		}
	};

	// FUNCTION: BETA10 0x1011d320
	unsigned char IsInitialized() const { return m_initialized; }

protected:
	list<MxDriver> m_list;       // 0x04
	unsigned char m_initialized; // 0x10
};

// TEMPLATE: BETA10 0x1011c1b0
// list<Direct3DDeviceInfo,allocator<Direct3DDeviceInfo> >::iterator::operator*

// TEMPLATE: BETA10 0x1011c200
// list<Direct3DDeviceInfo,allocator<Direct3DDeviceInfo> >::iterator::operator++

// TEMPLATE: BETA10 0x1011c290
// list<Direct3DDeviceInfo,allocator<Direct3DDeviceInfo> >::begin

// TEMPLATE: BETA10 0x1011c300
// list<Direct3DDeviceInfo,allocator<Direct3DDeviceInfo> >::end

// TEMPLATE: BETA10 0x1011c4d0
// list<MxDriver,allocator<MxDriver> >::iterator::operator*

// TEMPLATE: BETA10 0x1011c520
// list<MxDriver,allocator<MxDriver> >::iterator::operator++

// TEMPLATE: BETA10 0x1011c560
// list<MxDriver,allocator<MxDriver> >::iterator::operator++

// TEMPLATE: BETA10 0x1011c590
// list<MxDriver,allocator<MxDriver> >::_Acc::_Next

// TEMPLATE: BETA10 0x1011c5b0
// list<MxDriver,allocator<MxDriver> >::begin

// TEMPLATE: BETA10 0x1011c5f0
// list<MxDriver,allocator<MxDriver> >::iterator::iterator

// TEMPLATE: BETA10 0x1011c620
// list<MxDriver,allocator<MxDriver> >::end

// TEMPLATE: BETA10 0x1011c690
// ??9@YAHABViterator@?$list@UMxDriver@@V?$allocator@UMxDriver@@@@@@0@Z

// TEMPLATE: BETA10 0x1011c770
// ??9@YAHABViterator@?$list@UDirect3DDeviceInfo@@V?$allocator@UDirect3DDeviceInfo@@@@@@0@Z

// TEMPLATE: BETA10 0x1011d3a0
// list<MxDriver,allocator<MxDriver> >::size

// TEMPLATE: BETA10 0x1011d3c0
// list<Direct3DDeviceInfo,allocator<Direct3DDeviceInfo> >::size

// TEMPLATE: BETA10 0x1011d3e0
// list<Direct3DDeviceInfo,allocator<Direct3DDeviceInfo> >::erase

// TEMPLATE: BETA10 0x1011d570
// list<MxDriver,allocator<MxDriver> >::erase

// TEMPLATE: BETA10 0x1011d6a0
// list<MxDriver,allocator<MxDriver> >::_Freenode

// TEMPLATE: BETA10 0x1011d700
// list<MxDriver,allocator<MxDriver> >::front

// TEMPLATE: BETA10 0x1011f750
// list<MxDriver,allocator<MxDriver> >::back

// TEMPLATE: BETA10 0x1011f780
// list<MxDriver,allocator<MxDriver> >::iterator::operator--

// TEMPLATE: BETA10 0x1011f7b0
// list<MxDriver,allocator<MxDriver> >::push_back

// TEMPLATE: BETA10 0x1011f830
// list<MxDriver,allocator<MxDriver> >::insert

// TEMPLATE: BETA10 0x1011f960
// list<MxDisplayMode,allocator<MxDisplayMode> >::push_back

// TEMPLATE: BETA10 0x1011fa90
// list<Direct3DDeviceInfo,allocator<Direct3DDeviceInfo> >::push_back

#endif // MXDIRECTXINFO_H
