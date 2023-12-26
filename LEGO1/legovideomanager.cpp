#include "legovideomanager.h"

DECOMP_SIZE_ASSERT(LegoVideoManager, 0x590);

// FUNCTION: LEGO1 0x1007aa20
LegoVideoManager::LegoVideoManager()
{
	m_unk0x64 = 0;
	m_3dManager = NULL;
	m_unk0x6c = 0;
	m_direct3d = 0;
	m_unk0xe6 = FALSE;
	memset(m_unk0x78, 0, sizeof(m_unk0x78));
	m_unk0x78[0] = 0x6c;
	m_unk0x4e8 = 0;
	m_isFullscreenMovie = FALSE;
	m_palette = NULL;
	m_prefCounter = NULL;
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
	// todo: delete m_unk0x4e8
	delete[] m_prefCounter;
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
	return FAILURE;
}

// STUB: LEGO1 0x1007ac40
MxResult LegoVideoManager::Create(MxVideoParam& p_videoParam, MxU32 p_frequencyMS, MxBool p_createThread)
{
	// TODO
	return MxVideoManager::Create(p_videoParam, p_frequencyMS, p_createThread);
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
		m_3dManager->GetLego3DView()->GetViewPort()->ForceUpdate(p_x, p_y, p_width, p_height);
	}
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
	m_3dManager->GetLego3DView()->GetViewPort()->SetBackgroundColor(p_red, p_green, p_blue);
}

// FUNCTION: LEGO1 0x1007c4c0
void LegoVideoManager::OverrideSkyColor(MxBool p_shouldOverride)
{
	this->m_videoParam.GetPalette()->SetOverrideSkyColor(p_shouldOverride);
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
