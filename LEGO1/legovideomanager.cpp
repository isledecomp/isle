#include "legovideomanager.h"
#include <ddraw.h>

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

// OFFSET: LEGO1 0x1007b6a0 STUB
void LegoVideoManager::MoveCursor(int x, int y)
{
  // TODO
}

// OFFSET: LEGO1 0x1007c440
void LegoVideoManager::SetSkyColor(float red, float green, float blue)
{
  PALETTEENTRY colorStrucure; // [esp+0h] [ebp-4h] BYREF

  colorStrucure.peRed = (red* 255.0);
  colorStrucure.peGreen = (green * 255.0);
  colorStrucure.peBlue = (blue * 255.0);
  colorStrucure.peFlags = -124;
  // TODO
}
