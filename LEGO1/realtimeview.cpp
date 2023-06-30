#include "realtimeview.h"

// 0x10101048
float g_userMaxLod = 3.6f;

// 0x1010104c
float g_partsThreshold = 1000.0f;

// OFFSET: LEGO1 0x100a5e00
float RealtimeView::GetUserMaxLOD()
{
  // TODO
  return 0;
}

// OFFSET: LEGO1 0x100a5e10
float RealtimeView::GetPartsThreshold()
{
  return g_partsThreshold;
}

// OFFSET: LEGO1 0x100a5de0
void RealtimeView::SetUserMaxLOD(float p_lod)
{
  g_userMaxLod = p_lod;
}

// OFFSET: LEGO1 0x100a5df0
void RealtimeView::SetPartsThreshold(float p_threshold)
{
  g_partsThreshold = p_threshold;
}
