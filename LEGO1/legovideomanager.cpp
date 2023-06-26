#include "legovideomanager.h"
#include <ddraw.h>
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