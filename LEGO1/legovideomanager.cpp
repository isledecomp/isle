#include "legovideomanager.h"

// OFFSET: LEGO1 0x1007aa20 STUB
LegoVideoManager::LegoVideoManager()
{
  // TODO
}

// OFFSET: LEGO1 0x1007ab40 STUB
LegoVideoManager::~LegoVideoManager()
{
  // TODO
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

// OFFSET: LEGO1 0x1007b6a0
void LegoVideoManager::MoveCursor(int p_x, int p_y)
{
  m_cursorX = p_x;
  m_cursorY = p_y;
  m_cursorMoved = TRUE;
  if(623 < p_x)
  {
    m_cursorX = 623;
  }

  if (463 < p_y)
  {
    m_cursorY = 463;
  }
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
  //m_3dManager->m_pViewport->vtable1c(red, green, blue)
}
