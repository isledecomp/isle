#include "mxdirect3d.h"

DECOMP_SIZE_ASSERT(MxDirect3D, 0x894)

#if !defined(MXDIRECTX_FOR_CONFIG)
#define RELEASE(x)                                                                                                     \
	if (x != NULL) {                                                                                                   \
		x->Release();                                                                                                  \
		x = NULL;                                                                                                      \
	}

// FUNCTION: LEGO1 0x1009b0a0
MxDirect3D::MxDirect3D()
{
	this->m_pDirect3d = NULL;
	this->m_pDirect3dDevice = NULL;
	this->m_bTexturesDisabled = FALSE;
	this->m_assignedDevice = NULL;
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

	if (ret && D3DCreate() && D3DSetMode()) {
		success = TRUE;
	}

	if (!success) {
		FUN_1009d920();
	}

	return success;
}

// FUNCTION: LEGO1 0x1009b210
void MxDirect3D::Destroy()
{
	RELEASE(m_pDirect3dDevice);
	RELEASE(m_pDirect3d);

	if (this->m_assignedDevice) {
		delete m_assignedDevice;
		this->m_assignedDevice = NULL;
	}

	if (m_pCurrentDeviceModesList) {
		m_pCurrentDeviceModesList = NULL;
	}

	MxDirectDraw::Destroy();
}

// FUNCTION: LEGO1 0x1009b290
void MxDirect3D::DestroyButNotDirectDraw()
{
	RELEASE(m_pDirect3dDevice);
	RELEASE(m_pDirect3d);
	MxDirectDraw::DestroyButNotDirectDraw();
}

// FUNCTION: LEGO1 0x1009b2d0
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
BOOL MxDirect3D::D3DSetMode()
{
	if (m_assignedDevice->m_flags & MxAssignedDevice::c_hardwareMode) {
		if (m_bOnlySoftRender) {
			Error("Failed to place vital surfaces in video memory for hardware driver", DDERR_GENERIC);
			return FALSE;
		}

		if (m_assignedDevice->m_desc.dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE) {
			m_bTexturesDisabled = FALSE;
		}
		else {
			m_bTexturesDisabled = TRUE;
		}

		if (!CreateZBuffer(DDSCAPS_VIDEOMEMORY, ZBufferDepth(m_assignedDevice))) {
			return FALSE;
		}
	}
	else {
		if (m_assignedDevice->m_desc.dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE) {
			m_bTexturesDisabled = FALSE;
		}
		else {
			m_bTexturesDisabled = TRUE;
		}

		if (!CreateZBuffer(DDSCAPS_SYSTEMMEMORY, ZBufferDepth(m_assignedDevice))) {
			return FALSE;
		}
	}

	HRESULT result = m_pDirect3d->CreateDevice(m_assignedDevice->m_guid, m_pBackBuffer, &m_pDirect3dDevice);

	if (result != DD_OK) {
		Error("Create D3D device failed", result);
		return FALSE;
	}

	DeviceModesInfo::Mode mode = m_currentMode;

	if (IsFullScreen()) {
		if (!IsSupportedMode(mode.width, mode.height, mode.bitsPerPixel)) {
			Error("This device cannot support the current display mode", DDERR_GENERIC);
			return FALSE;
		}
	}

	LPDIRECTDRAWSURFACE frontBuffer = m_pFrontBuffer;
	LPDIRECTDRAWSURFACE backBuffer = m_pBackBuffer;

	DDSURFACEDESC desc;
	memset(&desc, 0, sizeof(desc));
	desc.dwSize = sizeof(desc);

	if (backBuffer->Lock(NULL, &desc, DDLOCK_WAIT, NULL) == DD_OK) {
		unsigned char* surface = (unsigned char*) desc.lpSurface;

		for (int i = mode.height; i > 0; i--) {
			memset(surface, 0, mode.width * desc.ddpfPixelFormat.dwRGBBitCount / 8);
			surface += desc.lPitch;
		}

		backBuffer->Unlock(desc.lpSurface);
	}
	else {
		OutputDebugString("MxDirect3D::D3DSetMode() back lock failed\n");
	}

	if (m_bFullScreen) {
		memset(&desc, 0, sizeof(desc));
		desc.dwSize = sizeof(desc);

		if (frontBuffer->Lock(NULL, &desc, DDLOCK_WAIT, NULL) == DD_OK) {
			unsigned char* surface = (unsigned char*) desc.lpSurface;

			for (int i = mode.height; i > 0; i--) {
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
	if (m_assignedDevice) {
		delete m_assignedDevice;
		m_assignedDevice = NULL;
		m_pCurrentDeviceModesList = NULL;
	}

	MxAssignedDevice* assignedDevice = new MxAssignedDevice;
	int i = 0;

	for (list<MxDriver>::iterator it = p_deviceEnumerate.m_list.begin(); it != p_deviceEnumerate.m_list.end(); it++) {
		MxDriver& driver = *it;

		if (&driver == p_driver) {
			assignedDevice->m_deviceInfo = new DeviceModesInfo;

			if (driver.m_guid) {
				assignedDevice->m_deviceInfo->m_guid = new GUID;
				memcpy(assignedDevice->m_deviceInfo->m_guid, driver.m_guid, sizeof(GUID));
			}

			assignedDevice->m_deviceInfo->m_count = driver.m_displayModes.size();

			if (assignedDevice->m_deviceInfo->m_count > 0) {
				assignedDevice->m_deviceInfo->m_modeArray =
					new DeviceModesInfo::Mode[assignedDevice->m_deviceInfo->m_count];

				int j = 0;
				for (list<MxDisplayMode>::iterator it2 = driver.m_displayModes.begin();
					 it2 != driver.m_displayModes.end();
					 it2++) {
					assignedDevice->m_deviceInfo->m_modeArray[j].width = (*it2).m_width;
					assignedDevice->m_deviceInfo->m_modeArray[j].height = (*it2).m_height;
					assignedDevice->m_deviceInfo->m_modeArray[j].bitsPerPixel = (*it2).m_bitsPerPixel;
					j++;
				}
			}

			memcpy(
				&assignedDevice->m_deviceInfo->m_ddcaps,
				&driver.m_ddCaps,
				sizeof(assignedDevice->m_deviceInfo->m_ddcaps)
			);

			if (i == 0) {
				assignedDevice->m_flags |= MxAssignedDevice::c_primaryDevice;
			}

			for (list<Direct3DDeviceInfo>::iterator it2 = driver.m_devices.begin(); it2 != driver.m_devices.end();
				 it2++) {
				Direct3DDeviceInfo& device = *it2;
				if (&device != p_device) {
					continue;
				}

				memcpy(&assignedDevice->m_guid, device.m_guid, sizeof(assignedDevice->m_guid));

				D3DDEVICEDESC* desc;
				if (device.m_HWDesc.dcmColorModel) {
					assignedDevice->m_flags |= MxAssignedDevice::c_hardwareMode;
					desc = &device.m_HWDesc;
				}
				else {
					desc = &device.m_HELDesc;
				}

				memcpy(&assignedDevice->m_desc, desc, sizeof(assignedDevice->m_desc));
				m_assignedDevice = assignedDevice;
				m_pCurrentDeviceModesList = assignedDevice->m_deviceInfo;
				break;
			}
		}

		i++;
	}

	if (!m_assignedDevice) {
		delete assignedDevice;
		return FALSE;
	}

	return TRUE;
}

#endif
