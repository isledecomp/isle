#include "mxdirect3d.h"

#include <stdio.h> // for vsprintf

DECOMP_SIZE_ASSERT(MxDeviceModeFinder, 0xe4);
DECOMP_SIZE_ASSERT(MxDirect3D, 0x894);
DECOMP_SIZE_ASSERT(MxDevice, 0x1a4);
DECOMP_SIZE_ASSERT(MxDisplayMode, 0x0c);
DECOMP_SIZE_ASSERT(MxDriver, 0x190);
DECOMP_SIZE_ASSERT(MxDeviceEnumerate, 0x14);

// FUNCTION: LEGO1 0x1009b0a0
MxDirect3D::MxDirect3D()
{
	this->m_pDirect3d = NULL;
	this->m_pDirect3dDevice = NULL;
	this->m_unk0x88c = NULL;
	this->m_pDeviceModeFinder = NULL;
}

// FUNCTION: LEGO1 0x1009b140
MxDirect3D::~MxDirect3D()
{
	Destroy();
}

// FUNCTION: LEGO1 0x1009b1a0
BOOL MxDirect3D::Create(
	HWND hWnd,
	BOOL fullscreen_1,
	BOOL surface_fullscreen,
	BOOL onlySystemMemory,
	int width,
	int height,
	int bpp,
	const PALETTEENTRY* pPaletteEntries,
	int paletteEntryCount
)
{
	BOOL success = FALSE;

	BOOL ret = MxDirectDraw::Create(
		hWnd,
		fullscreen_1,
		surface_fullscreen,
		onlySystemMemory,
		width,
		height,
		bpp,
		pPaletteEntries,
		paletteEntryCount
	);

	if (ret && CreateIDirect3D() && D3DSetMode())
		success = TRUE;

	if (!success)
		FUN_1009d920();

	return success;
}

// FUNCTION: LEGO1 0x1009b210
void MxDirect3D::Destroy()
{
	if (this->m_pDirect3dDevice) {
		this->m_pDirect3dDevice->Release();
		this->m_pDirect3dDevice = NULL;
	}

	if (this->m_pDirect3d) {
		this->m_pDirect3d->Release();
		this->m_pDirect3d = NULL;
	}

	if (this->m_pDeviceModeFinder) {
		delete m_pDeviceModeFinder;
		this->m_pDeviceModeFinder = NULL;
	}

	// This should get deleted by MxDirectDraw::Destroy
	if (m_pCurrentDeviceModesList) {
		// delete m_pCurrentDeviceModesList; // missing?
		m_pCurrentDeviceModesList = NULL;
	}

	MxDirectDraw::Destroy();
}

// FUNCTION: LEGO1 0x1009b290
void MxDirect3D::DestroyButNotDirectDraw()
{
	if (this->m_pDirect3dDevice) {
		this->m_pDirect3dDevice->Release();
		this->m_pDirect3dDevice = NULL;
	}
	if (this->m_pDirect3d) {
		this->m_pDirect3d->Release();
		this->m_pDirect3d = NULL;
	}
	MxDirectDraw::DestroyButNotDirectDraw();
}

// FUNCTION: LEGO1 0x1009b2d0
BOOL MxDirect3D::CreateIDirect3D()
{
	MxResult ret = IDirect3D_QueryInterface(m_pDirectDraw, IID_IDirect3D2, (LPVOID*) &m_pDirect3d);

	if (ret) {
		Error("Creation of IDirect3D failed", ret);
		return FALSE;
	}

	return TRUE;
}

// STUB: LEGO1 0x1009b310
BOOL MxDirect3D::D3DSetMode()
{
	// TODO
	// if (m_pDeviceModeFinder)
	Error("This device cannot support the current display mode", 0);
	OutputDebugString("MxDirect3D::D3DSetMode() front lock failed\n");
	OutputDebugString("MxDirect3D::D3DSetMode() back lock failed\n");
	return TRUE;
}

// STUB: LEGO1 0x1009b5f0
BOOL MxDirect3D::FUN_1009b5f0(MxDeviceEnumerate& p_deviceEnumerator, MxDriver* p_driver, MxDevice* p_device)
{
	return TRUE;
}

// FUNCTION: LEGO1 0x1009b8b0
MxDeviceModeFinder::MxDeviceModeFinder()
{
	memset(this, 0, sizeof(*this));
}

// FUNCTION: LEGO1 0x1009b8d0
MxDeviceModeFinder::~MxDeviceModeFinder()
{
	if (m_deviceInfo) {
		delete m_deviceInfo;
		m_deviceInfo = NULL;
	}
}

// FUNCTION: LEGO1 0x1009ba80
MxDriver::MxDriver(LPGUID p_guid, LPSTR p_driverDesc, LPSTR p_driverName)
{
	m_guid = NULL;
	m_driverDesc = NULL;
	m_driverName = NULL;
	memset(&m_ddCaps, 0, sizeof(m_ddCaps));

	Init(p_guid, p_driverDesc, p_driverName);
}

// FUNCTION: LEGO1 0x1009bb80
MxDriver::~MxDriver()
{
	if (m_guid)
		delete m_guid;
	if (m_driverDesc)
		delete[] m_driverDesc;
	if (m_driverName)
		delete[] m_driverName;
}

// FUNCTION: LEGO1 0x1009bc30
void MxDriver::Init(LPGUID p_guid, LPSTR p_driverDesc, LPSTR p_driverName)
{
	if (m_driverDesc) {
		delete[] m_driverDesc;
		m_driverDesc = NULL;
	}

	if (m_driverName) {
		delete[] m_driverName;
		m_driverName = NULL;
	}

	if (p_guid) {
		m_guid = new GUID;
		memcpy(m_guid, p_guid, sizeof(*m_guid));
	}

	if (p_driverDesc) {
		m_driverDesc = new char[strlen(p_driverDesc) + 1];
		strcpy(m_driverDesc, p_driverDesc);
	}

	if (p_driverName) {
		m_driverName = new char[strlen(p_driverName) + 1];
		strcpy(m_driverName, p_driverName);
	}
}

// FUNCTION: LEGO1 0x1009bd20
MxDevice::MxDevice(
	LPGUID p_guid,
	LPSTR p_deviceDesc,
	LPSTR p_deviceName,
	LPD3DDEVICEDESC p_HWDesc,
	LPD3DDEVICEDESC p_HELDesc
)
{
	memset(this, 0, sizeof(*this));

	Init(p_guid, p_deviceDesc, p_deviceName, p_HWDesc, p_HELDesc);
}

// FUNCTION: LEGO1 0x1009bd60
MxDevice::~MxDevice()
{
	if (m_guid)
		delete m_guid;
	if (m_deviceDesc)
		delete[] m_deviceDesc;
	if (m_deviceName)
		delete[] m_deviceName;
}

// FUNCTION: LEGO1 0x1009bda0
void MxDevice::Init(
	LPGUID p_guid,
	LPSTR p_deviceDesc,
	LPSTR p_deviceName,
	LPD3DDEVICEDESC p_HWDesc,
	LPD3DDEVICEDESC p_HELDesc
)
{
	if (m_deviceDesc) {
		delete[] m_deviceDesc;
		m_deviceDesc = NULL;
	}

	if (m_deviceName) {
		delete[] m_deviceName;
		m_deviceName = NULL;
	}

	if (p_guid) {
		m_guid = new GUID;
		memcpy(m_guid, p_guid, sizeof(*m_guid));
	}

	if (p_deviceDesc) {
		m_deviceDesc = new char[strlen(p_deviceDesc) + 1];
		strcpy(m_deviceDesc, p_deviceDesc);
	}

	if (p_deviceName) {
		m_deviceName = new char[strlen(p_deviceName) + 1];
		strcpy(m_deviceName, p_deviceName);
	}

	if (p_HWDesc)
		memcpy(&m_HWDesc, p_HWDesc, sizeof(m_HWDesc));

	if (p_HELDesc)
		memcpy(&m_HELDesc, p_HELDesc, sizeof(m_HELDesc));
}

// FUNCTION: LEGO1 0x1009bec0
MxDeviceEnumerate::MxDeviceEnumerate()
{
	m_initialized = FALSE;
}

// FUNCTION: LEGO1 0x1009c070
BOOL MxDeviceEnumerate::EnumDirectDrawCallback(LPGUID p_guid, LPSTR p_driverDesc, LPSTR p_driverName)
{
	MxDriver driver(p_guid, p_driverDesc, p_driverName);
	m_list.push_back(driver);

	// Must be zeroed because held resources are copied by pointer only
	// and should not be freed at the end of this function
	driver.m_guid = NULL;
	driver.m_driverDesc = NULL;
	driver.m_driverName = NULL;
	memset(&driver.m_ddCaps, 0, sizeof(driver.m_ddCaps));

	LPDIRECT3D2 lpDirect3d2 = NULL;
	LPDIRECTDRAW lpDD = NULL;
	MxDriver& newDevice = m_list.back();
	HRESULT result = DirectDrawCreate(newDevice.m_guid, &lpDD, NULL);

	if (result != DD_OK)
		BuildErrorString("DirectDraw Create failed: %s\n", EnumerateErrorToString(result));
	else {
		lpDD->EnumDisplayModes(0, NULL, this, DisplayModesEnumerateCallback);
		newDevice.m_ddCaps.dwSize = sizeof(newDevice.m_ddCaps);
		result = lpDD->GetCaps(&newDevice.m_ddCaps, NULL);

		if (result != DD_OK)
			BuildErrorString("GetCaps failed: %s\n", EnumerateErrorToString(result));
		else {
			result = lpDD->QueryInterface(IID_IDirect3D2, (LPVOID*) &lpDirect3d2);

			if (result != DD_OK)
				BuildErrorString("D3D creation failed: %s\n", EnumerateErrorToString(result));
			else {
				result = lpDirect3d2->EnumDevices(DevicesEnumerateCallback, this);

				if (result != DD_OK)
					BuildErrorString("D3D enum devices failed: %s\n", EnumerateErrorToString(result));
				else {
					if (newDevice.m_devices.empty()) {
						m_list.pop_back();
					}
				}
			}
		}
	}

	if (lpDirect3d2)
		lpDirect3d2->Release();

	if (lpDD)
		lpDD->Release();

	return DDENUMRET_OK;
}

// FUNCTION: LEGO1 0x1009c4c0
void MxDeviceEnumerate::BuildErrorString(const char* p_format, ...)
{
	va_list args;
	char buf[512];

	va_start(args, p_format);
	vsprintf(buf, p_format, args);
	va_end(args);

	OutputDebugString(buf);
}

// FUNCTION: LEGO1 0x1009c4f0
HRESULT CALLBACK MxDeviceEnumerate::DisplayModesEnumerateCallback(LPDDSURFACEDESC p_ddsd, LPVOID p_context)
{
	MxDeviceEnumerate* deviceEnumerate = (MxDeviceEnumerate*) p_context;
	return deviceEnumerate->EnumDisplayModesCallback(p_ddsd);
}

// FUNCTION: LEGO1 0x1009c510
HRESULT CALLBACK MxDeviceEnumerate::DevicesEnumerateCallback(
	LPGUID p_guid,
	LPSTR p_deviceDesc,
	LPSTR p_deviceName,
	LPD3DDEVICEDESC p_HWDesc,
	LPD3DDEVICEDESC p_HELDesc,
	LPVOID p_context
)
{
	MxDeviceEnumerate* deviceEnumerate = (MxDeviceEnumerate*) p_context;
	return deviceEnumerate->EnumDevicesCallback(p_guid, p_deviceDesc, p_deviceName, p_HWDesc, p_HELDesc);
}

// FUNCTION: LEGO1 0x1009c540
HRESULT MxDeviceEnumerate::EnumDisplayModesCallback(LPDDSURFACEDESC p_ddsd)
{
	MxDisplayMode displayMode;
	displayMode.m_width = p_ddsd->dwWidth;
	displayMode.m_height = p_ddsd->dwHeight;
	displayMode.m_bitsPerPixel = p_ddsd->ddpfPixelFormat.dwRGBBitCount;

	m_list.back().m_displayModes.push_back(displayMode);
	return DDENUMRET_OK;
}

// FUNCTION: LEGO1 0x1009c5d0
HRESULT MxDeviceEnumerate::EnumDevicesCallback(
	LPGUID p_guid,
	LPSTR p_deviceDesc,
	LPSTR p_deviceName,
	LPD3DDEVICEDESC p_HWDesc,
	LPD3DDEVICEDESC p_HELDesc
)
{
	MxDevice device(p_guid, p_deviceDesc, p_deviceName, p_HWDesc, p_HELDesc);
	m_list.back().m_devices.push_back(device);
	memset(&device, 0, sizeof(device));
	return DDENUMRET_OK;
}

// FUNCTION: LEGO1 0x1009c6c0
MxResult MxDeviceEnumerate::DoEnumerate()
{
	if (m_initialized)
		return FAILURE;

	HRESULT ret = DirectDrawEnumerate(DirectDrawEnumerateCallback, this);
	if (ret) {
		BuildErrorString("DirectDrawEnumerate returned error %s\n", EnumerateErrorToString(ret));
		return FAILURE;
	}

	m_initialized = TRUE;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1009c710
BOOL CALLBACK
MxDeviceEnumerate::DirectDrawEnumerateCallback(LPGUID p_guid, LPSTR p_driverDesc, LPSTR p_driverName, LPVOID p_context)
{
	MxDeviceEnumerate* deviceEnumerate = (MxDeviceEnumerate*) p_context;
	return deviceEnumerate->EnumDirectDrawCallback(p_guid, p_driverDesc, p_driverName);
}

// STUB: LEGO1 0x1009c730
const char* MxDeviceEnumerate::EnumerateErrorToString(HRESULT p_error)
{
	// TODO: This is a list of error messages, similar to the function in
	// MxDirectDraw, except that this one now contains the Direct3D errors.
	// Probably just copied from a sample file in the dx5 sdk.
	return "";
}

// FUNCTION: LEGO1 0x1009ce60
MxS32 MxDeviceEnumerate::ParseDeviceName(const char* p_deviceId)
{
	if (!m_initialized)
		return -1;

	MxS32 num = -1;
	MxS32 hex[4];

	if (sscanf(p_deviceId, "%d 0x%x 0x%x 0x%x 0x%x", &num, &hex[0], &hex[1], &hex[2], &hex[3]) != 5)
		return -1;

	if (num < 0)
		return -1;

	GUID guid;
	memcpy(&guid, hex, sizeof(guid));

	MxS32 result = ProcessDeviceBytes(num, guid);

	if (result < 0)
		return ProcessDeviceBytes(-1, guid);
	return result;
}

// FUNCTION: LEGO1 0x1009cf20
MxS32 MxDeviceEnumerate::ProcessDeviceBytes(MxS32 p_deviceNum, GUID& p_guid)
{
	if (!m_initialized)
		return -1;

	MxS32 i = 0;
	MxS32 j = 0;

	struct GUID4 {
		MxS32 m_data1;
		MxS32 m_data2;
		MxS32 m_data3;
		MxS32 m_data4;
	};

	static_assert(sizeof(GUID4) == sizeof(GUID), "Equal size");

	GUID4 deviceGuid;
	memcpy(&deviceGuid, &p_guid, sizeof(GUID4));

	for (list<MxDriver>::iterator it = m_list.begin(); it != m_list.end(); it++) {
		if (p_deviceNum >= 0 && p_deviceNum < i)
			return -1;

		GUID4 compareGuid;
		MxDriver& driver = *it;
		for (list<MxDevice>::iterator it2 = driver.m_devices.begin(); it2 != driver.m_devices.end(); it2++) {
			memcpy(&compareGuid, (*it2).m_guid, sizeof(GUID4));

			if (compareGuid.m_data1 == deviceGuid.m_data1 && compareGuid.m_data2 == deviceGuid.m_data2 &&
				compareGuid.m_data3 == deviceGuid.m_data3 && compareGuid.m_data4 == deviceGuid.m_data4 &&
				i == p_deviceNum)
				return j;

			j++;
		}

		i++;
	}

	return -1;
}

// FUNCTION: LEGO1 0x1009d030
MxResult MxDeviceEnumerate::GetDevice(MxS32 p_deviceNum, MxDriver*& p_driver, MxDevice*& p_device)
{
	if (p_deviceNum >= 0 && m_initialized) {
		MxS32 i = 0;

		for (list<MxDriver>::iterator it = m_list.begin(); it != m_list.end(); it++) {
			p_driver = &*it;

			for (list<MxDevice>::iterator it2 = p_driver->m_devices.begin(); it2 != p_driver->m_devices.end(); it2++) {
				if (i == p_deviceNum) {
					p_device = &*it2;
					return SUCCESS;
				}
				i++;
			}
		}

		return FAILURE;
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x1009d0d0
MxS32 MxDeviceEnumerate::FUN_1009d0d0()
{
	if (!m_initialized)
		return -1;

	if (m_list.empty())
		return -1;

	MxS32 i = 0;
	MxS32 j = 0;
	MxS32 k = -1;
	MxU32 und = FUN_1009d1a0();

	for (list<MxDriver>::iterator it = m_list.begin();; it++) {
		if (it == m_list.end())
			return k;

		for (list<MxDevice>::iterator it2 = (*it).m_devices.begin(); it2 != (*it).m_devices.end(); it2++) {
			if ((*it2).m_HWDesc.dcmColorModel)
				return j;

			if ((und && (*it2).m_HELDesc.dcmColorModel == D3DCOLOR_RGB && i == 0) ||
				(*it2).m_HELDesc.dcmColorModel == D3DCOLOR_MONO && i == 0 && k < 0)
				k = j;

			j++;
		}

		i++;
	}

	return -1;
}

// STUB: LEGO1 0x1009d1a0
undefined4 MxDeviceEnumerate::FUN_1009d1a0()
{
	return 1;
}

// STUB: LEGO1 0x1009d1e0
undefined4 MxDeviceEnumerate::FUN_1009d1e0()
{
	return 1;
}

// FUNCTION: LEGO1 0x1009d210
MxResult MxDeviceEnumerate::FUN_1009d210()
{
	if (!m_initialized)
		return FAILURE;

	for (list<MxDriver>::iterator it = m_list.begin(); it != m_list.end();) {
		MxDriver& driver = *it;

		if (!FUN_1009d370(driver))
			m_list.erase(it++);
		else {
			for (list<MxDevice>::iterator it2 = driver.m_devices.begin(); it2 != driver.m_devices.end();) {
				MxDevice& device = *it2;

				if (!FUN_1009d3d0(device))
					driver.m_devices.erase(it2++);
				else
					it2++;
			}

			if (driver.m_devices.empty())
				m_list.erase(it++);
			else
				it++;
		}
	}

	return m_list.empty() ? FAILURE : SUCCESS;
}

// FUNCTION: LEGO1 0x1009d370
MxBool MxDeviceEnumerate::FUN_1009d370(MxDriver& p_driver)
{
	for (list<MxDisplayMode>::iterator it = p_driver.m_displayModes.begin(); it != p_driver.m_displayModes.end();
		 it++) {
		if ((*it).m_width == 640 && (*it).m_height == 480) {
			if ((*it).m_bitsPerPixel == 8 || (*it).m_bitsPerPixel == 16)
				return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x1009d3d0
MxBool MxDeviceEnumerate::FUN_1009d3d0(MxDevice& p_device)
{
	if (m_list.size() <= 0)
		return FALSE;

	if (p_device.m_HWDesc.dcmColorModel)
		return p_device.m_HWDesc.dwDeviceZBufferBitDepth & DDBD_16 && p_device.m_HWDesc.dpcTriCaps.dwTextureCaps & 1;

	for (list<MxDevice>::iterator it = m_list.front().m_devices.begin(); it != m_list.front().m_devices.end(); it++) {
		if ((&*it) == &p_device)
			return TRUE;
	}

	return FALSE;
}
