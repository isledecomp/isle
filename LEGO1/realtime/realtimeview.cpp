#include "realtimeview.h"

#include <math.h>

// GLOBAL: LEGO1 0x10109598
// GLOBAL: BETA10 0x10211dc0
float g_userMaxLodPower;

// GLOBAL: LEGO1 0x10101044
// GLOBAL: BETA10 0x10204fd8
float g_userMaxBase = 4.0f;

// GLOBAL: LEGO1 0x10101048
// GLOBAL: BETA10 0x10204fdc
float g_userMaxLod = 3.6f;

// GLOBAL: LEGO1 0x1010104c
// GLOBAL: BETA10 0x10204fe0
float g_partsThreshold = 1000.0f;

// FUNCTION: LEGO1 0x100a5dc0
// FUNCTION: BETA10 0x10168840
RealtimeView::RealtimeView()
{
	UpdateMaxLOD();
}

// FUNCTION: LEGO1 0x100a5dd0
RealtimeView::~RealtimeView()
{
}

// FUNCTION: LEGO1 0x100a5de0
// FUNCTION: BETA10 0x10168874
void RealtimeView::SetUserMaxLOD(float p_lod)
{
	g_userMaxLod = p_lod;
	UpdateMaxLOD();
}

// FUNCTION: LEGO1 0x100a5df0
// FUNCTION: BETA10 0x10168891
void RealtimeView::SetPartsThreshold(float p_threshold)
{
	g_partsThreshold = p_threshold;
}

// FUNCTION: LEGO1 0x100a5e00
// FUNCTION: BETA10 0x101688a9
float RealtimeView::GetUserMaxLOD()
{
	return g_userMaxLod;
}

// FUNCTION: LEGO1 0x100a5e10
// FUNCTION: BETA10 0x101688bf
float RealtimeView::GetPartsThreshold()
{
	return g_partsThreshold;
}

// FUNCTION: LEGO1 0x100a5e20
// FUNCTION: BETA10 0x101688d5
void RealtimeView::UpdateMaxLOD()
{
	g_userMaxLodPower = pow(g_userMaxBase, -g_userMaxLod);
}
