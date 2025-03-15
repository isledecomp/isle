#include "mxdirect3d.h"

#include <assert.h>

DECOMP_SIZE_ASSERT(MxDirect3D, 0x894)

#if !defined(MXDIRECTX_FOR_CONFIG)
#define RELEASE(x)                                                                                                     \
	if (x != NULL) {                                                                                                   \
		x->Release();                                                                                                  \
		x = NULL;                                                                                                      \
	}

// FUNCTION: LEGO1 0x1009b0a0
// FUNCTION: BETA10 0x1011b220
MxDirect3D::MxDirect3D()
{
	m_pDirect3d = NULL;
	m_pDirect3dDevice = NULL;
	m_bTexturesDisabled = FALSE;
	m_currentDeviceInfo = NULL;
}

// FUNCTION: LEGO1 0x1009b140
// FUNCTION: BETA10 0x1011b2c3
MxDirect3D::~MxDirect3D()
{
	Destroy();
}

// FUNCTION: LEGO1 0x1009b1a0
// FUNCTION: BETA10 0x1011b333
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
	assert(m_currentDeviceInfo);

	if (!MxDirectDraw::Create(
			hWnd,
			fullscreen_1,
			surface_fullscreen,
			onlySystemMemory,
			width,
			height,
			bpp,
			pPaletteEntries,
			paletteEntryCount
		)) {
		goto done;
	}

	if (!D3DCreate()) {
		goto done;
	}

	if (!D3DSetMode()) {
		goto done;
	}

	success = TRUE;

done:
	if (!success) {
		FUN_1009d920();
	}

	return success;
}

// FUNCTION: LEGO1 0x1009b210
// FUNCTION: BETA10 0x1011b41d
void MxDirect3D::Destroy()
{
	RELEASE(m_pDirect3dDevice);
	RELEASE(m_pDirect3d);

	if (m_currentDeviceInfo) {
		delete m_currentDeviceInfo;
		m_currentDeviceInfo = NULL;
	}

	if (m_currentDevInfo) {
		m_currentDevInfo = NULL;
	}

	MxDirectDraw::Destroy();
}

// FUNCTION: LEGO1 0x1009b290
// FUNCTION: BETA10 0x1011b50a
void MxDirect3D::DestroyButNotDirectDraw()
{
	RELEASE(m_pDirect3dDevice);
	RELEASE(m_pDirect3d);
	MxDirectDraw::DestroyButNotDirectDraw();
}

// FUNCTION: LEGO1 0x1009b2d0
// FUNCTION: BETA10 0x1011b592
BOOL MxDirect3D::D3DCreate()
{
	HRESULT result;

	result = DirectDraw()->QueryInterface(IID_IDirect3D2, (LPVOID*) &m_pDirect3d);
	if (result != DD_OK) {
		Error("Creation of IDirect3D failed", result);
		return FALSE;
	}
	return TRUE;
}

// FUNCTION: LEGO1 0x1009b310
// FUNCTION: BETA10 0x1011b617
BOOL MxDirect3D::D3DSetMode()
{
	assert(m_currentDeviceInfo);

	if (m_currentDeviceInfo->m_flags & MxAssignedDevice::c_hardwareMode) {
		if (m_bOnlySoftRender) {
			Error("Failed to place vital surfaces in video memory for hardware driver", DDERR_GENERIC);
			return FALSE;
		}

		if (m_currentDeviceInfo->m_desc.dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE) {
			m_bTexturesDisabled = FALSE;
		}
		else {
			m_bTexturesDisabled = TRUE;
		}

		if (!CreateZBuffer(DDSCAPS_VIDEOMEMORY, ZBufferDepth(m_currentDeviceInfo))) {
			return FALSE;
		}
	}
	else {
		if (m_currentDeviceInfo->m_desc.dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE) {
			m_bTexturesDisabled = FALSE;
		}
		else {
			m_bTexturesDisabled = TRUE;
		}

		if (!CreateZBuffer(DDSCAPS_SYSTEMMEMORY, ZBufferDepth(m_currentDeviceInfo))) {
			return FALSE;
		}
	}

	LPDIRECTDRAWSURFACE backBuf = BackBuffer();
	HRESULT result = m_pDirect3d->CreateDevice(m_currentDeviceInfo->m_guid, backBuf, &m_pDirect3dDevice);

	if (result != DD_OK) {
		Error("Create D3D device failed", result);
		return FALSE;
	}

	DeviceModesInfo::Mode mode = *CurrentMode();

	if (IsFullScreen()) {
		if (!IsSupportedMode(mode.width, mode.height, mode.bitsPerPixel)) {
			Error("This device cannot support the current display mode", DDERR_GENERIC);
			return FALSE;
		}
	}

	LPDIRECTDRAWSURFACE frontBuffer = FrontBuffer();
	LPDIRECTDRAWSURFACE backBuffer = BackBuffer();

	DDSURFACEDESC desc;
	memset(&desc, 0, sizeof(desc));
	desc.dwSize = sizeof(desc);

	if (backBuffer->Lock(NULL, &desc, DDLOCK_WAIT, NULL) == DD_OK) {
		unsigned char* surface = (unsigned char*) desc.lpSurface;

		for (int i = 0; i < mode.height; i++) {
			memset(surface, 0, mode.width * desc.ddpfPixelFormat.dwRGBBitCount / 8);
			surface += desc.lPitch;
		}

		backBuffer->Unlock(desc.lpSurface);
	}
	else {
		OutputDebugString("MxDirect3D::D3DSetMode() back lock failed\n");
	}

	if (IsFullScreen()) {
		memset(&desc, 0, sizeof(desc));
		desc.dwSize = sizeof(desc);

		if (frontBuffer->Lock(NULL, &desc, DDLOCK_WAIT, NULL) == DD_OK) {
			unsigned char* surface = (unsigned char*) desc.lpSurface;

			for (int i = 0; i < mode.height; i++) {
				memset(surface, 0, mode.width * desc.ddpfPixelFormat.dwRGBBitCount / 8);
				surface += desc.lPitch;
			}

			frontBuffer->Unlock(desc.lpSurface);
		}
		else {
			OutputDebugString("MxDirect3D::D3DSetMode() front lock failed\n");
		}
	}

	return TRUE;
}

// FUNCTION: LEGO1 0x1009b5a0
// FUNCTION: BETA10 0x1011babb
int MxDirect3D::ZBufferDepth(MxAssignedDevice* p_assignedDevice)
{
	int depth;
	DWORD deviceDepth;

	if (p_assignedDevice->m_desc.dwFlags & D3DDD_DEVICEZBUFFERBITDEPTH) {
		deviceDepth = p_assignedDevice->m_desc.dwDeviceZBufferBitDepth;
	}
	else {
		deviceDepth = 0;
	}

	if (deviceDepth & DDBD_32) {
		depth = 32;
	}
	else if (deviceDepth & DDBD_24) {
		depth = 24;
	}
	else if (deviceDepth & DDBD_16) {
		depth = 16;
	}
	else if (deviceDepth & DDBD_8) {
		depth = 8;
	}
	else {
		depth = -1;
	}

	return depth;
}

// FUNCTION: LEGO1 0x1009b5f0
// FUNCTION: BETA10 0x1011bbca
BOOL MxDirect3D::SetDevice(MxDeviceEnumerate& p_deviceEnumerate, MxDriver* p_driver, Direct3DDeviceInfo* p_device)
{
	if (m_currentDeviceInfo) {
		delete m_currentDeviceInfo;
		m_currentDeviceInfo = NULL;
		m_currentDevInfo = NULL;
	}

	MxAssignedDevice* d = new MxAssignedDevice;
	assert(d);
	int i = 0;

	for (list<MxDriver>::iterator it = p_deviceEnumerate.m_list.begin(); it != p_deviceEnumerate.m_list.end();
		 it++, i++) {
		MxDriver& driver = *it;

		if (&driver == p_driver) {
			d->m_deviceInfo = new DeviceModesInfo;

			if (driver.m_guid) {
				d->m_deviceInfo->m_guid = new GUID;
				*d->m_deviceInfo->m_guid = *driver.m_guid;
			}

			d->m_deviceInfo->m_count = driver.m_displayModes.size();

			if (d->m_deviceInfo->m_count > 0) {
				int j = 0;
				d->m_deviceInfo->m_modeArray = new DeviceModesInfo::Mode[d->m_deviceInfo->m_count];

				for (list<MxDisplayMode>::iterator it2 = driver.m_displayModes.begin();
					 it2 != driver.m_displayModes.end();
					 it2++, j++) {
					d->m_deviceInfo->m_modeArray[j].width = (*it2).m_width;
					d->m_deviceInfo->m_modeArray[j].height = (*it2).m_height;
					d->m_deviceInfo->m_modeArray[j].bitsPerPixel = (*it2).m_bitsPerPixel;
				}
			}

			d->m_deviceInfo->m_ddcaps = driver.m_ddCaps;

			if (i == 0) {
				d->m_flags |= MxAssignedDevice::c_primaryDevice;
			}

			for (list<Direct3DDeviceInfo>::iterator it2 = driver.m_devices.begin(); it2 != driver.m_devices.end();
				 it2++) {
				Direct3DDeviceInfo& device = *it2;
				if (&device == p_device) {
					memcpy(&d->m_guid, device.m_guid, sizeof(d->m_guid));

					if (device.m_HWDesc.dcmColorModel) {
						d->m_flags |= MxAssignedDevice::c_hardwareMode;
						d->m_desc = device.m_HWDesc;
					}
					else {
						d->m_desc = device.m_HELDesc;
					}

					m_currentDeviceInfo = d;
					m_currentDevInfo = d->m_deviceInfo;
					break;
				}
			}
		}
	}

	if (!m_currentDeviceInfo) {
		delete d;
		return FALSE;
	}
	else {
		return TRUE;
	}
}

#endif
