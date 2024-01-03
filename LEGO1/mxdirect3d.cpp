#include "mxdirect3d.h"

#include <stdio.h> // for vsprintf

DECOMP_SIZE_ASSERT(MxDeviceModeFinder, 0xe4);
DECOMP_SIZE_ASSERT(MxDirect3D, 0x894);
DECOMP_SIZE_ASSERT(MxDeviceEnumerate0x178Element, 0x1a4);
DECOMP_SIZE_ASSERT(MxDeviceDisplayMode, 0x0c);
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

// FUNCTION: LEGO1 0x1009bec0
MxDeviceEnumerate::MxDeviceEnumerate()
{
	m_unk0x10 = FALSE;
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

	LPDIRECTDRAW lpDD = NULL;
	LPDIRECT3D2 lpDirect3d2 = NULL;
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
					if (newDevice.m_unk0x178.empty()) {
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

// STUB: LEGO1 0x1009c510
HRESULT CALLBACK MxDeviceEnumerate::DevicesEnumerateCallback(
	LPGUID p_lpGuid,
	LPSTR p_lpDeviceDescription,
	LPSTR p_lpDeviceName,
	LPD3DDEVICEDESC p_pHWDesc,
	LPD3DDEVICEDESC p_pHELDesc,
	LPVOID p_context
)
{
	return TRUE;
}

// FUNCTION: LEGO1 0x1009c540
HRESULT MxDeviceEnumerate::EnumDisplayModesCallback(LPDDSURFACEDESC p_ddsd)
{
	MxDeviceDisplayMode displayMode;
	displayMode.m_width = p_ddsd->dwWidth;
	displayMode.m_height = p_ddsd->dwHeight;
	displayMode.m_bitsPerPixel = p_ddsd->ddpfPixelFormat.dwRGBBitCount;

	m_list.back().m_displayModes.push_back(displayMode);
	return DDENUMRET_OK;
}

// FUNCTION: LEGO1 0x1009c6c0
MxResult MxDeviceEnumerate::DoEnumerate()
{
	if (m_unk0x10)
		return FAILURE;

	HRESULT ret = DirectDrawEnumerate(DirectDrawEnumerateCallback, this);
	if (ret) {
		BuildErrorString("DirectDrawEnumerate returned error %s\n", EnumerateErrorToString(ret));
		return FAILURE;
	}

	m_unk0x10 = TRUE;
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

// STUB: LEGO1 0x1009ce60
MxS32 MxDeviceEnumerate::ParseDeviceName(const char* p_deviceId)
{
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
