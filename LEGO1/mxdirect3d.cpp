#include "mxdirect3d.h"

#include <stdio.h> // for vsprintf

DECOMP_SIZE_ASSERT(MxDeviceModeFinder, 0xe4);
DECOMP_SIZE_ASSERT(MxDirect3D, 0x894);
DECOMP_SIZE_ASSERT(MxDevice, 0x1a4);
DECOMP_SIZE_ASSERT(MxDisplayMode, 0x0c);
DECOMP_SIZE_ASSERT(MxDeviceEnumerateElement, 0x190);
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
BOOL MxDirect3D::FUN_1009b5f0(MxDeviceEnumerate& p_deviceEnumerate, undefined* p_und1, undefined* p_und2)
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
MxDeviceEnumerateElement::MxDeviceEnumerateElement(LPGUID p_guid, LPSTR p_driverDesc, LPSTR p_driverName)
{
	m_guid = NULL;
	m_driverDesc = NULL;
	m_driverName = NULL;
	memset(&m_ddCaps, 0, sizeof(m_ddCaps));

	Init(p_guid, p_driverDesc, p_driverName);
}

// FUNCTION: LEGO1 0x1009bb80
MxDeviceEnumerateElement::~MxDeviceEnumerateElement()
{
	if (m_guid)
		delete m_guid;
	if (m_driverDesc)
		delete[] m_driverDesc;
	if (m_driverName)
		delete[] m_driverName;
}

// FUNCTION: LEGO1 0x1009bc30
void MxDeviceEnumerateElement::Init(LPGUID p_guid, LPSTR p_driverDesc, LPSTR p_driverName)
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
	MxDeviceEnumerateElement device(p_guid, p_driverDesc, p_driverName);
	m_list.push_back(device);

	// Must be zeroed because held resources are copied by pointer only
	// and should not be freed at the end of this function
	device.m_guid = NULL;
	device.m_driverDesc = NULL;
	device.m_driverName = NULL;
	memset(&device.m_ddCaps, 0, sizeof(device.m_ddCaps));

	LPDIRECT3D2 lpDirect3d2 = NULL;
	LPDIRECTDRAW lpDD = NULL;
	MxDeviceEnumerateElement& newDevice = m_list.back();
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

	DeviceHex deviceHex;
	memcpy(&deviceHex, hex, sizeof(deviceHex));

	MxS32 result = ProcessDeviceBytes(num, deviceHex);

	if (result < 0)
		return ProcessDeviceBytes(-1, deviceHex);
	return result;
}

// FUNCTION: LEGO1 0x1009cf20
MxS32 MxDeviceEnumerate::ProcessDeviceBytes(MxS32 p_num, DeviceHex& p_deviceHex)
{
	if (!m_initialized)
		return -1;

	MxS32 i = 0;
	MxS32 j = 0;
	DeviceHex deviceHex = p_deviceHex;

	for (list<MxDeviceEnumerateElement>::iterator it = m_list.begin(); it != m_list.end(); it++) {
		if (p_num >= 0 && p_num < i)
			return -1;

		MxDeviceEnumerateElement& elem = *it;
		for (list<MxDevice>::iterator it2 = elem.m_devices.begin(); it2 != elem.m_devices.end(); it2++) {
			DeviceHex guidHex;
			memcpy(&guidHex, (*it2).m_guid, sizeof(GUID));

			if (deviceHex.hex1 == guidHex.hex1 && deviceHex.hex2 == guidHex.hex2 && deviceHex.hex3 == guidHex.hex3 &&
				deviceHex.hex4 == guidHex.hex4 && i == p_num)
				return j;

			j++;
		}

		i++;
	}

	return -1;
}

// STUB: LEGO1 0x1009d030
MxResult MxDeviceEnumerate::FUN_1009d030(MxS32 p_und1, undefined** p_und2, undefined** p_und3)
{
	return FAILURE;
}

// STUB: LEGO1 0x1009d0d0
MxResult MxDeviceEnumerate::FUN_1009d0d0()
{
	return FAILURE;
}

// STUB: LEGO1 0x1009d210
MxResult MxDeviceEnumerate::FUN_1009d210()
{
	return FAILURE;
}
