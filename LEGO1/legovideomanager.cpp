#include "legovideomanager.h"

DECOMP_SIZE_ASSERT(LegoVideoManager, 0x590);

// OFFSET: LEGO1 0x1007aa20
LegoVideoManager::LegoVideoManager()
{
	m_unk64 = 0;
	m_3dManager = NULL;
	m_unk6c = 0;
	m_direct3d = 0;
	m_unk0xe6 = FALSE;
	memset(m_unk0x78, 0, sizeof(m_unk0x78));
	m_unk0x78[0] = 0x6c;
	m_unk4e8 = 0;
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

// OFFSET: LEGO1 0x1007ab40
LegoVideoManager::~LegoVideoManager()
{
	Destroy();
	delete m_palette;
}

// OFFSET: LEGO1 0x1007b5e0
void LegoVideoManager::Destroy()
{
	// todo: delete m_unk0x512
	// todo: delete m_unk0x258
	if (m_arialFont != NULL) {
		DeleteObject(m_arialFont);
		m_arialFont = NULL;
	}

	// delete m_unk64; //TODO: delete d3drm

	delete m_3dManager;
	MxVideoManager::Destroy();
	// todo: delete m_unk4e8
	delete[] m_prefCounter;
}

// OFFSET: LEGO1 0x1007b6a0
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

// OFFSET: LEGO1 0x1007c300
void LegoVideoManager::EnableFullScreenMovie(MxBool p_enable)
{
	EnableFullScreenMovie(p_enable, TRUE);
}

// OFFSET: LEGO1 0x1007c310 STUB
void LegoVideoManager::EnableFullScreenMovie(MxBool p_enable, MxBool p_scale)
{
	// TODO
}

// OFFSET: LEGO1 0x1007c440
void LegoVideoManager::SetSkyColor(float p_red, float p_green, float p_blue)
{
	PALETTEENTRY colorStrucure;

	colorStrucure.peRed = (p_red * 255.0f);
	colorStrucure.peGreen = (p_green * 255.0f);
	colorStrucure.peBlue = (p_blue * 255.0f);
	colorStrucure.peFlags = -124;
	m_videoParam.GetPalette()->SetSkyColor(&colorStrucure);
	m_videoParam.GetPalette()->SetOverrideSkyColor(TRUE);

	// TODO 3d manager
	// m_3dManager->m_pViewport->vtable1c(red, green, blue)
}

// OFFSET: LEGO1 0x1007c560 STUB
int LegoVideoManager::EnableRMDevice()
{
	// TODO
	return 0;
}

// OFFSET: LEGO1 0x1007c740 STUB
int LegoVideoManager::DisableRMDevice()
{
	// TODO
	return 0;
}
