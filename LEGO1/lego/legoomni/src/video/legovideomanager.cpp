#include "legovideomanager.h"

#include "3dmanager/lego3dmanager.h"
#include "legoinputmanager.h"
#include "legomain.h"
#include "misc.h"
#include "mxdirectx/legodxinfo.h"
#include "mxdirectx/mxdirect3d.h"
#include "mxdirectx/mxstopwatch.h"
#include "mxdisplaysurface.h"
#include "mxmisc.h"
#include "mxpalette.h"
#include "mxregion.h"
#include "mxtimer.h"
#include "mxtransitionmanager.h"
#include "realtime/matrix.h"
#include "realtime/realtime.h"
#include "roi/legoroi.h"
#include "tgl/d3drm/impl.h"
#include "viewmanager/viewroi.h"

#include <stdio.h>

DECOMP_SIZE_ASSERT(LegoVideoManager, 0x590)
DECOMP_SIZE_ASSERT(MxStopWatch, 0x18)
DECOMP_SIZE_ASSERT(MxFrequencyMeter, 0x20)

// FUNCTION: LEGO1 0x1007aa20
LegoVideoManager::LegoVideoManager()
{
	m_renderer = NULL;
	m_3dManager = NULL;
	m_viewROI = NULL;
	m_direct3d = NULL;
	m_unk0xe6 = FALSE;
	memset(m_unk0x78, 0, sizeof(m_unk0x78));
	m_unk0x78[0] = 0x6c;
	m_phonemeRefList = NULL;
	m_isFullscreenMovie = FALSE;
	m_palette = NULL;
	m_stopWatch = NULL;
	m_drawCursor = FALSE;
	m_cursorX = m_cursorY;
	m_cursorYCopy = m_cursorY;
	m_cursorXCopy = m_cursorY;
	m_cursorSurface = NULL;
	m_fullScreenMovie = FALSE;
	m_drawFPS = FALSE;
	m_unk0x528 = NULL;
	m_arialFont = NULL;
	m_unk0xe5 = FALSE;
	m_unk0x554 = FALSE;
	m_paused = FALSE;
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
	if (!m_direct3d) {
		m_direct3d = new MxDirect3D;
	}

	return m_direct3d ? SUCCESS : FAILURE;
}

// FUNCTION: LEGO1 0x1007ac40
// FUNCTION: BETA10 0x100d5cf4
MxResult LegoVideoManager::Create(MxVideoParam& p_videoParam, MxU32 p_frequencyMS, MxBool p_createThread)
{
	MxResult result = FAILURE;
	MxBool paletteCreated = FALSE;
	MxS32 deviceNum = -1;
	Direct3DDeviceInfo* device = NULL;
	MxDriver* driver = NULL;
	LegoDeviceEnumerate deviceEnumerate;
	Mx3DPointFloat posVec(0.0, 1.25, -50.0);
	Mx3DPointFloat dirVec(0.0, 0.0, 1.0);
	Mx3DPointFloat upVec(0.0, 1.0, 0.0);
	MxMatrix outMatrix;
	HWND hwnd = MxOmni::GetInstance()->GetWindowHandle();
	MxS32 bits = p_videoParam.Flags().Get16Bit() ? 16 : 8;

	if (!p_videoParam.GetPalette()) {
		MxPalette* palette = new MxPalette;
		p_videoParam.SetPalette(palette);

		if (!p_videoParam.GetPalette()) {
			goto done;
		}
		paletteCreated = TRUE;
	}

	PALETTEENTRY paletteEntries[256];
	p_videoParam.GetPalette()->GetEntries(paletteEntries);

	if (CreateDirect3D() != SUCCESS) {
		goto done;
	}

	if (deviceEnumerate.DoEnumerate() != SUCCESS) {
		goto done;
	}

	if (p_videoParam.GetDeviceName()) {
		deviceNum = deviceEnumerate.ParseDeviceName(p_videoParam.GetDeviceName());
		if (deviceNum >= 0) {
			if ((deviceNum = deviceEnumerate.GetDevice(deviceNum, driver, device)) != SUCCESS) {
				deviceNum = -1;
			}
		}
	}

	if (deviceNum < 0) {
		deviceEnumerate.FUN_1009d210();
		deviceNum = deviceEnumerate.FUN_1009d0d0();
		deviceNum = deviceEnumerate.GetDevice(deviceNum, driver, device);
	}

	m_direct3d->SetDevice(deviceEnumerate, driver, device);

	if (!driver->m_ddCaps.dwCaps2 && driver->m_ddCaps.dwSVBRops[7] != 2) {
		p_videoParam.Flags().SetF2bit0(TRUE);
	}
	else {
		p_videoParam.Flags().SetF2bit0(FALSE);
	}

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
		)) {
		goto done;
	}

	if (MxVideoManager::VTable0x28(
			p_videoParam,
			m_direct3d->DirectDraw(),
			m_direct3d->Direct3D(),
			m_direct3d->FrontBuffer(),
			m_direct3d->BackBuffer(),
			m_direct3d->Clipper(),
			p_frequencyMS,
			p_createThread
		) != SUCCESS) {
		goto done;
	}

	m_renderer = Tgl::CreateRenderer();

	if (!m_renderer) {
		goto done;
	}

	m_3dManager = new Lego3DManager;

	if (!m_3dManager) {
		goto done;
	}

	Lego3DManager::CreateStruct createStruct;
	memset(&createStruct, 0, sizeof(createStruct));
	createStruct.m_hWnd = LegoOmni::GetInstance()->GetWindowHandle();
	createStruct.m_pDirectDraw = m_pDirectDraw;
	createStruct.m_pFrontBuffer = m_displaySurface->GetDirectDrawSurface1();
	createStruct.m_pBackBuffer = m_displaySurface->GetDirectDrawSurface2();
	createStruct.m_pPalette = m_videoParam.GetPalette()->CreateNativePalette();
	createStruct.m_isFullScreen = FALSE;
	createStruct.m_isWideViewAngle = m_videoParam.Flags().GetWideViewAngle();
	createStruct.m_direct3d = m_direct3d->Direct3D();
	createStruct.m_d3dDevice = m_direct3d->Direct3DDevice();

	if (!m_3dManager->Create(createStruct)) {
		goto done;
	}

	ViewLODList* pLODList;

	if (ConfigureD3DRM() != SUCCESS) {
		goto done;
	}

	pLODList = m_3dManager->GetViewLODListManager()->Create("CameraROI", 1);
	m_viewROI = new TimeROI(m_renderer, pLODList, Timer()->GetTime());
	pLODList->Release();

	CalcLocalTransform(posVec, dirVec, upVec, outMatrix);
	m_viewROI->WrappedSetLocalTransform(outMatrix);

	m_3dManager->Add(*m_viewROI);
	m_3dManager->SetPointOfView(*m_viewROI);

	m_phonemeRefList = new LegoPhonemeList;
	SetRender3D(FALSE);
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
// FUNCTION: BETA10 0x100d6816
void LegoVideoManager::Destroy()
{
	if (m_cursorSurface != NULL) {
		m_cursorSurface->Release();
		m_cursorSurface = NULL;
	}

	if (m_unk0x528 != NULL) {
		m_unk0x528->Release();
		m_unk0x528 = NULL;
	}

	if (m_arialFont != NULL) {
		DeleteObject(m_arialFont);
		m_arialFont = NULL;
	}

	delete m_renderer;

	if (m_viewROI != NULL) {
		if (m_3dManager != NULL) {
			m_3dManager->Remove(*m_viewROI);
		}

		delete m_viewROI;
	}

	delete m_3dManager;
	MxVideoManager::Destroy();
	delete m_phonemeRefList;
	delete m_stopWatch;
}

// FUNCTION: LEGO1 0x1007b6a0
void LegoVideoManager::MoveCursor(MxS32 p_cursorX, MxS32 p_cursorY)
{
	m_cursorX = p_cursorX;
	m_cursorY = p_cursorY;
	m_drawCursor = TRUE;

	if (623 < p_cursorX) {
		m_cursorX = 623;
	}

	if (463 < p_cursorY) {
		m_cursorY = 463;
	}
}

// FUNCTION: LEGO1 0x1007b6f0
void LegoVideoManager::ToggleFPS(MxBool p_visible)
{
	if (p_visible && !m_drawFPS) {
		m_drawFPS = TRUE;
		m_unk0x550 = 1.0;
		m_unk0x54c = Timer()->GetTime();
	}
	else {
		m_drawFPS = p_visible;
	}
}

// FUNCTION: LEGO1 0x1007b770
MxResult LegoVideoManager::Tickle()
{
	if (m_unk0x554 && !m_videoParam.Flags().GetFlipSurfaces() &&
		TransitionManager()->GetTransitionType() == MxTransitionManager::e_idle) {
		Sleep(30);
	}

	m_stopWatch->Stop();
	m_elapsedSeconds = m_stopWatch->ElapsedSeconds();
	m_stopWatch->Reset();
	m_stopWatch->Start();

	m_direct3d->RestoreSurfaces();

	SortPresenterList();

	MxPresenter* presenter;
	MxPresenterListCursor cursor(m_presenters);

	while (cursor.Next(presenter)) {
		presenter->Tickle();
	}

	if (m_render3d && !m_paused) {
		m_3dManager->GetLego3DView()->GetView()->Clear();
	}

	MxRect32 rect(0, 0, m_videoParam.GetRect().GetWidth() - 1, m_videoParam.GetRect().GetHeight() - 1);
	InvalidateRect(rect);

	if (!m_paused && (m_render3d || m_unk0xe5)) {
		cursor.Reset();

		while (cursor.Next(presenter) && presenter->GetDisplayZ() >= 0) {
			presenter->PutData();
		}

		if (!m_unk0xe5) {
			m_3dManager->Render(0.0);
			m_3dManager->GetLego3DView()->GetDevice()->Update();
		}

		cursor.Prev();

		while (cursor.Next(presenter)) {
			presenter->PutData();
		}

		if (m_drawCursor) {
			DrawCursor();
		}

		if (m_drawFPS) {
			DrawFPS();
		}
	}
	else if (m_fullScreenMovie) {
		MxPresenter* presenter;
		MxPresenterListCursor cursor(m_presenters);

		if (cursor.Last(presenter)) {
			presenter->PutData();
		}
	}

	if (!m_paused) {
		if (m_render3d && m_videoParam.Flags().GetFlipSurfaces()) {
			m_3dManager->GetLego3DView()
				->GetView()
				->ForceUpdate(0, 0, m_videoParam.GetRect().GetWidth(), m_videoParam.GetRect().GetHeight());
		}

		UpdateRegion();
	}

	m_region->Reset();
	return SUCCESS;
}

inline void LegoVideoManager::DrawCursor()
{
	if (m_cursorX != m_cursorXCopy || m_cursorY != m_cursorYCopy) {
		if (m_cursorX >= 0 && m_cursorY >= 0) {
			m_cursorXCopy = m_cursorX;
			m_cursorYCopy = m_cursorY;
		}
	}

	LPDIRECTDRAWSURFACE ddSurface2 = m_displaySurface->GetDirectDrawSurface2();

	if (!m_cursorSurface) {
		m_cursorRect.top = 0;
		m_cursorRect.left = 0;
		m_cursorRect.bottom = 16;
		m_cursorRect.right = 16;
		m_cursorSurface = MxDisplaySurface::CreateCursorSurface();

		if (!m_cursorSurface) {
			m_drawCursor = FALSE;
		}
	}

	ddSurface2
		->BltFast(m_cursorXCopy, m_cursorYCopy, m_cursorSurface, &m_cursorRect, DDBLTFAST_WAIT | DDBLTFAST_SRCCOLORKEY);
}

// FUNCTION: LEGO1 0x1007bbc0
void LegoVideoManager::DrawFPS()
{
	char zeros[8] = "0000.00";
	if (m_unk0x528 == NULL) {
		m_arialFont = CreateFontA(
			12,
			0,
			0,
			0,
			FW_NORMAL,
			FALSE,
			FALSE,
			FALSE,
			ANSI_CHARSET,
			OUT_DEFAULT_PRECIS,
			CLIP_DEFAULT_PRECIS,
			DEFAULT_QUALITY,
			FF_DONTCARE | VARIABLE_PITCH,
			"Arial"
		);
		HDC dc = GetDC(NULL);
		SelectObject(dc, m_arialFont);
		GetTextExtentPointA(dc, zeros, strlen(zeros), &m_fpsSize);
		ReleaseDC(NULL, dc);
		m_unk0x528 = m_displaySurface->FUN_100bc8b0();
		SetRect(&this->m_fpsRect, 0, 0, m_fpsSize.cx, m_fpsSize.cy);
		if (m_unk0x528 == NULL) {
			DeleteObject(m_arialFont);
			m_arialFont = NULL;
			return;
		}
		DDCOLORKEY color_key;
		color_key.dwColorSpaceHighValue = 0;
		color_key.dwColorSpaceLowValue = 0;
		m_unk0x528->SetColorKey(DDCKEY_SRCBLT, &color_key);
		DDSURFACEDESC surfaceDesc = {0};
		surfaceDesc.dwSize = sizeof(surfaceDesc);
		if (m_unk0x528->Lock(NULL, &surfaceDesc, DDLOCK_WAIT, NULL) != DD_OK) {
			m_unk0x528->Release();
			DeleteObject(m_arialFont);
			m_unk0x528 = NULL;
			m_arialFont = NULL;
		}
		else {
			DWORD i;
			char* ptr = (char*) surfaceDesc.lpSurface;
			for (i = 0; i < surfaceDesc.dwHeight; i++) {
				memset(ptr, 0, surfaceDesc.dwWidth * surfaceDesc.ddpfPixelFormat.dwRGBBitCount / 8);
				ptr += surfaceDesc.lPitch;
			}
			m_unk0x528->Unlock(surfaceDesc.lpSurface);
			m_unk0x54c = Timer()->GetTime();
			m_unk0x550 = 1.f;
		}
	}
	else {
		MxTimer* timer = Timer();
		if (timer->GetTime() <= m_unk0x54c + 5000.f) {
			m_unk0x550 += 1.f;
		}
		else {
			char buffer[32];
			int nb = sprintf(buffer, "%.02f", m_unk0x550 / (Timer()->GetTime() - m_unk0x54c) / 1000.f);
			m_unk0x54c = Timer()->GetTime();
			DDSURFACEDESC surfaceDesc = {0};
			surfaceDesc.dwSize = sizeof(surfaceDesc);
			if (m_unk0x528->Lock(NULL, &surfaceDesc, DDLOCK_WAIT, NULL) == DD_OK) {
				DWORD i;
				char* ptr = (char*) surfaceDesc.lpSurface;
				for (i = 0; i < surfaceDesc.dwHeight; i++) {
					memset(ptr, 0, surfaceDesc.dwWidth * surfaceDesc.ddpfPixelFormat.dwRGBBitCount / 8);
					ptr += surfaceDesc.lPitch;
				}
				m_unk0x528->Unlock(surfaceDesc.lpSurface);
			}
			HDC dc;
			if (m_unk0x528->GetDC(&dc) != DD_OK) {
				m_unk0x528->Release();
				m_unk0x528 = NULL;
				DeleteObject(m_arialFont);
				m_arialFont = NULL;
				return;
			}
			SelectObject(dc, m_arialFont);
			SetTextColor(dc, RGB(0xff, 0xff, 0x00));
			SetBkColor(dc, RGB(0x00, 0x00, 0x00));
			SetBkMode(dc, OPAQUE);
			GetTextExtentPoint32A(dc, buffer, nb, &m_fpsSize);
			RECT rect;
			SetRect(&rect, 0, 0, m_fpsSize.cx, m_fpsSize.cy);
			ExtTextOutA(dc, 0, 0, ETO_OPAQUE, &rect, buffer, nb, NULL);
			m_unk0x528->ReleaseDC(dc);
			m_unk0x550 = 1.f;
		}
		if (m_unk0x528 != NULL) {
			m_displaySurface->GetDirectDrawSurface2()
				->BltFast(20, 20, m_unk0x528, &m_fpsRect, DDBLTFAST_WAIT | DDBLTFAST_SRCCOLORKEY);
			m_3dManager->GetLego3DView()->GetView()->ForceUpdate(20, 20, m_fpsRect.right, m_fpsRect.bottom);
		}
	}
}

// FUNCTION: LEGO1 0x1007c080
MxPresenter* LegoVideoManager::GetPresenterAt(MxS32 p_x, MxS32 p_y)
{
	MxPresenterListCursor cursor(m_presenters);
	MxPresenter* presenter;

	while (cursor.Prev(presenter)) {
		if (presenter->IsHit(p_x, p_y)) {
			return presenter;
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x1007c180
// FUNCTION: BETA10 0x100d6df4
MxPresenter* LegoVideoManager::GetPresenterByActionObjectName(const char* p_actionObjectName)
{
	MxPresenterListCursor cursor(m_presenters);
	MxPresenter* presenter;

	while (TRUE) {
		if (!cursor.Prev(presenter)) {
			return NULL;
		}

		if (!presenter->GetAction()) {
			continue;
		}

		if (strcmpi(presenter->GetAction()->GetObjectName(), p_actionObjectName) == 0) {
			return presenter;
		}
	}
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

// FUNCTION: LEGO1 0x1007c2d0
MxResult LegoVideoManager::ResetPalette(MxBool p_ignoreSkyColor)
{
	MxResult result = FAILURE;

	if (m_videoParam.GetPalette() != NULL) {
		m_videoParam.GetPalette()->Reset(p_ignoreSkyColor);
		m_displaySurface->SetPalette(m_videoParam.GetPalette());
		result = SUCCESS;
	}

	return result;
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

			m_render3d = FALSE;
			m_fullScreenMovie = TRUE;
		}
		else {
			m_displaySurface->ClearScreen();
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

			m_render3d = TRUE;
			m_fullScreenMovie = FALSE;
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
void LegoVideoManager::UpdateView(MxU32 p_x, MxU32 p_y, MxU32 p_width, MxU32 p_height)
{
	if (p_width == 0) {
		p_width = m_videoParam.GetRect().GetWidth();
	}
	if (p_height == 0) {
		p_height = m_videoParam.GetRect().GetHeight();
	}

	if (!m_paused) {
		m_3dManager->GetLego3DView()->GetView()->ForceUpdate(p_x, p_y, p_width, p_height);
	}
}

// FUNCTION: LEGO1 0x1007c520
void LegoVideoManager::FUN_1007c520()
{
	m_unk0xe5 = TRUE;
	m_render3d = FALSE;
	m_videoParam.GetPalette()->SetOverrideSkyColor(FALSE);

	m_displaySurface->ClearScreen();
	InputManager()->EnableInputProcessing();
	InputManager()->SetUnknown335(TRUE);
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

	if (!d3drm) {
		return FAILURE;
	}

	MxAssignedDevice* assignedDevice = m_direct3d->AssignedDevice();

	if (assignedDevice && assignedDevice->GetFlags() & MxAssignedDevice::c_hardwareMode) {
		if (assignedDevice->GetDesc().dpcTriCaps.dwTextureFilterCaps & D3DPTFILTERCAPS_LINEAR) {
			d3drm->SetTextureQuality(D3DRMTEXTURE_LINEAR);
		}

		d3drm->SetDither(TRUE);

		if (assignedDevice->GetDesc().dpcTriCaps.dwShadeCaps & D3DPSHADECAPS_ALPHAFLATBLEND) {
			d3drm->SetRenderMode(D3DRMRENDERMODE_BLENDEDTRANSPARENCY);
		}
	}

	return SUCCESS;
}
