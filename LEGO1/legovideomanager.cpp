#include "legovideomanager.h"

#include "legoomni.h"
#include "legoroi.h"
#include "mxtimer.h"
#include "realtime/matrix.h"
#include "viewmanager/viewroi.h"

DECOMP_SIZE_ASSERT(LegoVideoManager, 0x590);
DECOMP_SIZE_ASSERT(MxStopWatch, 0x18);

// FUNCTION: LEGO1 0x1007aa20
LegoVideoManager::LegoVideoManager()
{
	m_renderer = NULL;
	m_3dManager = NULL;
	m_viewROI = NULL;
	m_direct3d = 0;
	m_unk0xe6 = FALSE;
	memset(m_unk0x78, 0, sizeof(m_unk0x78));
	m_unk0x78[0] = 0x6c;
	m_unk0x100d9d00 = NULL;
	m_isFullscreenMovie = FALSE;
	m_palette = NULL;
	m_stopWatch = NULL;
	m_cursorMoved = FALSE;
	m_cursorX = m_cursorY;
	m_cursorYCopy = m_cursorY;
	m_cursorXCopy = m_cursorY;
	m_unk0x514 = 0;
	m_unk0x500 = FALSE;
	m_drawFPS = FALSE;
	m_unk0x528 = 0;
	m_arialFont = NULL;
	m_unk0xe5 = FALSE;
	m_unk0x554 = 0;
	m_initialized = FALSE;
}

// FUNCTION: LEGO1 0x1007ab40
LegoVideoManager::~LegoVideoManager()
{
	Destroy();
	delete m_palette;
}

// FUNCTION: LEGO1 0x1007abb0
MxResult LegoVideoManager::CreateDirect3D()
{
	if (!m_direct3d)
		m_direct3d = new MxDirect3D;

	return m_direct3d ? SUCCESS : FAILURE;
}

// FUNCTION: LEGO1 0x1007ac40
MxResult LegoVideoManager::Create(MxVideoParam& p_videoParam, MxU32 p_frequencyMS, MxBool p_createThread)
{
	MxBool paletteCreated = FALSE;
	MxDriver* driver = NULL;
	MxDevice* device = NULL;
	MxResult result = FAILURE;

	MxDeviceEnumerate100d9cc8 deviceEnumerate;
	Vector3Data posVec(0.0, 1.25, -50.0);
	Vector3Data dirVec(0.0, 0.0, 1.0);
	Vector3Data upVec(0.0, 1.0, 0.0);
	Matrix4Data outMatrix;
	HWND hwnd = MxOmni::GetInstance()->GetWindowHandle();
	MxS32 bits = p_videoParam.Flags().Get16Bit() ? 16 : 8;
	MxS32 deviceNum = -1;

	if (!p_videoParam.GetPalette()) {
		MxPalette* palette = new MxPalette;
		p_videoParam.SetPalette(palette);

		if (!palette)
			goto done;
		paletteCreated = TRUE;
	}

	PALETTEENTRY paletteEntries[256];
	p_videoParam.GetPalette()->GetEntries(paletteEntries);

	if (CreateDirect3D() != SUCCESS)
		goto done;

	if (deviceEnumerate.DoEnumerate() != SUCCESS)
		goto done;

	if (p_videoParam.GetDeviceName()) {
		deviceNum = deviceEnumerate.ParseDeviceName(p_videoParam.GetDeviceName());
		if (deviceNum >= 0) {
			if ((deviceNum = deviceEnumerate.GetDevice(deviceNum, driver, device)) != SUCCESS)
				deviceNum = -1;
		}
	}

	if (deviceNum < 0) {
		deviceEnumerate.FUN_1009d210();
		deviceNum = deviceEnumerate.FUN_1009d0d0();
		deviceEnumerate.GetDevice(deviceNum, driver, device);
	}

	m_direct3d->SetDevice(deviceEnumerate, driver, device);

	if (!driver->m_ddCaps.dwCaps2 && driver->m_ddCaps.dwSVBRops[7] != 2)
		p_videoParam.Flags().SetF2bit0(TRUE);
	else
		p_videoParam.Flags().SetF2bit0(FALSE);

	ViewROI::SetUnk101013d8(p_videoParam.Flags().GetF2bit0() == FALSE);

	if (!m_direct3d->Create(
			hwnd,
			p_videoParam.Flags().GetFullScreen(),
			p_videoParam.Flags().GetFlipSurfaces(),
			p_videoParam.Flags().GetBackBuffers() == FALSE,
			p_videoParam.GetRect().GetWidth(),
			p_videoParam.GetRect().GetHeight(),
			bits,
			paletteEntries,
			sizeof(paletteEntries) / sizeof(paletteEntries[0])
		))
		goto done;

	if (MxVideoManager::VTable0x28(
			p_videoParam,
			m_direct3d->GetDirectDraw(),
			m_direct3d->GetDirect3D(),
			m_direct3d->GetFrontBuffer(),
			m_direct3d->GetBackBuffer(),
			m_direct3d->GetClipper(),
			p_frequencyMS,
			p_createThread
		) != SUCCESS)
		goto done;

	m_renderer = Tgl::CreateRenderer();

	if (!m_renderer)
		goto done;

	m_3dManager = new Lego3DManager;

	if (!m_3dManager)
		goto done;

	Lego3DManager::CreateStruct createStruct;
	memset(&createStruct, 0, sizeof(createStruct));
	createStruct.m_hwnd = LegoOmni::GetInstance()->GetWindowHandle();
	createStruct.m_directDraw = m_pDirectDraw;
	createStruct.m_ddSurface1 = m_displaySurface->GetDirectDrawSurface1();
	createStruct.m_ddSurface2 = m_displaySurface->GetDirectDrawSurface2();
	createStruct.m_ddPalette = m_videoParam.GetPalette()->CreateNativePalette();
	createStruct.m_isFullScreen = FALSE;
	createStruct.m_flags = m_videoParam.Flags().GetWideViewAngle();
	createStruct.m_direct3d = m_direct3d->GetDirect3D();
	createStruct.m_d3dDevice = m_direct3d->GetDirect3DDevice();

	if (!m_3dManager->Create(createStruct))
		goto done;

	ViewLODList* pLODList;

	if (ConfigureD3DRM() != SUCCESS)
		goto done;

	pLODList = m_3dManager->GetViewLODListManager()->Create("CameraROI", 1);
	m_viewROI = new LegoROI(m_renderer, pLODList, Timer()->GetTime());
	pLODList->Release();

	CalcLocalTransform(posVec, dirVec, upVec, outMatrix);
	m_viewROI->WrappedSetLocalTransform(outMatrix);

	m_3dManager->GetLego3DView()->FUN_100ab100(m_viewROI);
	m_3dManager->GetLego3DView()->FUN_100ab1b0(m_viewROI);

	m_unk0x100d9d00 = new MxUnknown100d9d00;
	m_unk0xe4 = FALSE;
	m_stopWatch = new MxStopWatch;
	m_stopWatch->Start();

	result = SUCCESS;

done:
	if (paletteCreated) {
		delete p_videoParam.GetPalette();
		p_videoParam.SetPalette(NULL);
	}

	return result;
}

// FUNCTION: LEGO1 0x1007b5e0
void LegoVideoManager::Destroy()
{
	// todo: delete m_unk0x512
	// todo: delete m_unk0x258
	if (m_arialFont != NULL) {
		DeleteObject(m_arialFont);
		m_arialFont = NULL;
	}

	// delete m_unk0x64; //TODO: delete d3drm

	delete m_3dManager;
	MxVideoManager::Destroy();
	delete m_stopWatch;
}

// FUNCTION: LEGO1 0x1007b6a0
void LegoVideoManager::MoveCursor(MxS32 p_cursorX, MxS32 p_cursorY)
{
	m_cursorX = p_cursorX;
	m_cursorY = p_cursorY;
	m_cursorMoved = TRUE;

	if (623 < p_cursorX)
		m_cursorX = 623;

	if (463 < p_cursorY)
		m_cursorY = 463;
}

// STUB: LEGO1 0x1007b770
MxResult LegoVideoManager::Tickle()
{
	// TODO
	return MxVideoManager::Tickle();
}

// STUB: LEGO1 0x1007c080
void LegoVideoManager::VTable0x38(undefined4, undefined4)
{
	// TODO
}

// FUNCTION: LEGO1 0x1007c290
MxResult LegoVideoManager::RealizePalette(MxPalette* p_pallete)
{
	if (p_pallete && m_videoParam.GetPalette()) {
		p_pallete->GetEntries(m_paletteEntries);
		m_videoParam.GetPalette()->SetEntries(m_paletteEntries);
		m_displaySurface->SetPalette(m_videoParam.GetPalette());
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1007c300
void LegoVideoManager::EnableFullScreenMovie(MxBool p_enable)
{
	EnableFullScreenMovie(p_enable, TRUE);
}

// FUNCTION: LEGO1 0x1007c310
void LegoVideoManager::EnableFullScreenMovie(MxBool p_enable, MxBool p_scale)
{
	if (m_isFullscreenMovie != p_enable) {
		m_isFullscreenMovie = p_enable;

		if (p_enable) {
			m_palette = m_videoParam.GetPalette()->Clone();
			OverrideSkyColor(FALSE);

			m_displaySurface->GetVideoParam().Flags().SetF1bit3(p_scale);

			m_unk0xe4 = FALSE;
			m_unk0x500 = TRUE;
		}
		else {
			m_displaySurface->FUN_100ba640();
			m_displaySurface->GetVideoParam().Flags().SetF1bit3(FALSE);

			// restore previous pallete
			RealizePalette(m_palette);
			delete m_palette;
			m_palette = NULL;

			// update region where video used to be
			MxRect32 rect(
				0,
				0,
				m_videoParam.GetRect().GetRight() - m_videoParam.GetRect().GetLeft(),
				m_videoParam.GetRect().GetBottom() - m_videoParam.GetRect().GetTop()
			);

			InvalidateRect(rect);
			UpdateRegion();
			OverrideSkyColor(TRUE);

			m_unk0xe4 = TRUE;
			m_unk0x500 = FALSE;
		}
	}

	if (p_enable) {
		m_displaySurface->GetVideoParam().Flags().SetF1bit3(p_scale);
	}
	else {
		m_displaySurface->GetVideoParam().Flags().SetF1bit3(FALSE);
	}
}

// FUNCTION: LEGO1 0x1007c440
void LegoVideoManager::SetSkyColor(float p_red, float p_green, float p_blue)
{
	PALETTEENTRY colorStrucure;

	colorStrucure.peRed = (p_red * 255.0f);
	colorStrucure.peGreen = (p_green * 255.0f);
	colorStrucure.peBlue = (p_blue * 255.0f);
	colorStrucure.peFlags = -124;
	m_videoParam.GetPalette()->SetSkyColor(&colorStrucure);
	m_videoParam.GetPalette()->SetOverrideSkyColor(TRUE);
	m_3dManager->GetLego3DView()->GetView()->SetBackgroundColor(p_red, p_green, p_blue);
}

// FUNCTION: LEGO1 0x1007c4c0
void LegoVideoManager::OverrideSkyColor(MxBool p_shouldOverride)
{
	this->m_videoParam.GetPalette()->SetOverrideSkyColor(p_shouldOverride);
}

// FUNCTION: LEGO1 0x1007c4d0
void LegoVideoManager::VTable0x34(MxU32 p_x, MxU32 p_y, MxU32 p_width, MxU32 p_height)
{
	if (p_width == 0) {
		p_width = m_videoParam.GetRect().GetWidth();
	}
	if (p_height == 0) {
		p_height = m_videoParam.GetRect().GetHeight();
	}

	if (!m_initialized) {
		m_3dManager->GetLego3DView()->GetView()->ForceUpdate(p_x, p_y, p_width, p_height);
	}
}

// STUB: LEGO1 0x1007c560
int LegoVideoManager::EnableRMDevice()
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x1007c740
int LegoVideoManager::DisableRMDevice()
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x1007c930
MxResult LegoVideoManager::ConfigureD3DRM()
{
	IDirect3DRMDevice2* d3drm =
		((TglImpl::DeviceImpl*) m_3dManager->GetLego3DView()->GetDevice())->ImplementationData();

	if (!d3drm)
		return FAILURE;

	MxAssignedDevice* assignedDevice = m_direct3d->GetAssignedDevice();

	if (assignedDevice && assignedDevice->GetFlags() & MxAssignedDevice::Flag_HardwareMode) {
		if (assignedDevice->GetDesc().dpcTriCaps.dwTextureFilterCaps & D3DPTFILTERCAPS_LINEAR)
			d3drm->SetTextureQuality(D3DRMTEXTURE_LINEAR);

		d3drm->SetDither(TRUE);

		if (assignedDevice->GetDesc().dpcTriCaps.dwShadeCaps & D3DPSHADECAPS_ALPHAFLATBLEND)
			d3drm->SetRenderMode(D3DRMRENDERMODE_BLENDEDTRANSPARENCY);
	}

	return SUCCESS;
}
