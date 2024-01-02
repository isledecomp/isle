#include "mxdirect3d.h"

#include <stdio.h> // for vsprintf

DECOMP_SIZE_ASSERT(MxDeviceModeFinder, 0xe4);
DECOMP_SIZE_ASSERT(MxDirect3D, 0x894);
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

// FUNCTION: LEGO1 0x1009bec0
MxDeviceEnumerate::MxDeviceEnumerate()
{
	m_unk0x10 = FALSE;
}

// STUB: LEGO1 0x1009c070
BOOL MxDeviceEnumerate::EnumDirectDrawCallback(GUID FAR* p_guid, LPSTR p_driverName, LPSTR p_driverDesc)
{
	// TODO
	// HRESULT ret = DirectDrawCreate();
	HRESULT ret = 0;
	if (ret) {
		BuildErrorString("GetCaps failed: %s\n", EnumerateErrorToString(ret));
	}
	// IDirect3D2_EnumDevices
	return TRUE;
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

// FUNCTION: LEGO1 0x1009c6c0
MxResult MxDeviceEnumerate::DoEnumerate()
{
	if (m_unk0x10)
		return FAILURE;

	HRESULT ret = DirectDrawEnumerate(EnumerateCallback, this);
	if (ret) {
		BuildErrorString("DirectDrawEnumerate returned error %s\n", EnumerateErrorToString(ret));
		return FAILURE;
	}

	m_unk0x10 = TRUE;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1009c710
BOOL CALLBACK EnumerateCallback(GUID FAR* p_guid, LPSTR p_driverName, LPSTR p_driverDesc, LPVOID p_context)
{
	MxDeviceEnumerate* deviceEnumerate = (MxDeviceEnumerate*) p_context;
	return deviceEnumerate->EnumDirectDrawCallback(p_guid, p_driverName, p_driverDesc);
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
