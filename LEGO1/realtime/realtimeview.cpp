#include "realtimeview.h"

#include <math.h>

// GLOBAL: LEGO1 0x10109598
float g_userMaxLodPower;

// GLOBAL: LEGO1 0x10101044
float g_userMaxBase = 4.0f;

// GLOBAL: LEGO1 0x10101048
float g_userMaxLod = 3.6f;

// GLOBAL: LEGO1 0x1010104c
float g_partsThreshold = 1000.0f;

// FUNCTION: LEGO1 0x100a5dc0
RealtimeView::RealtimeView()
{
	UpdateMaxLOD();
}

// FUNCTION: LEGO1 0x100a5dd0
RealtimeView::~RealtimeView()
{
}

// FUNCTION: LEGO1 0x100a5de0
void RealtimeView::SetUserMaxLOD(float p_lod)
{
	g_userMaxLod = p_lod;
	UpdateMaxLOD();
}

// FUNCTION: LEGO1 0x100a5df0
void RealtimeView::SetPartsThreshold(float p_threshold)
{
	g_partsThreshold = p_threshold;
}

// FUNCTION: LEGO1 0x100a5e00
float RealtimeView::GetUserMaxLOD()
{
	return g_userMaxLod;
}

// FUNCTION: LEGO1 0x100a5e10
float RealtimeView::GetPartsThreshold()
{
	return g_partsThreshold;
}

// FUNCTION: LEGO1 0x100a5e20
void RealtimeView::UpdateMaxLOD()
{
	g_userMaxLodPower = pow(g_userMaxBase, -g_userMaxLod);
}
