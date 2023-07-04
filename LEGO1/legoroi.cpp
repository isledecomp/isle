#include "legoroi.h"

// 0x10101368
int g_roiConfig = 100;

// OFFSET: LEGO1 0x100a9e10
void LegoROI::SetDisplayBB(int p_displayBB)
{
  // Intentionally empty function
}

// OFFSET: LEGO1 0x100a81c0
void LegoROI::configureLegoROI(int p_roi)
{
  g_roiConfig = p_roi;
}

