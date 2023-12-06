#include "legoutil.h"

#include "mxomni.h"
#include "mxtypes.h"

#include <string.h>

// FUNCTION: LEGO1 0x1003e300
ExtraActionType MatchActionString(const char* p_str)
{
	ExtraActionType result = ExtraActionType_unknown;

	if (!strcmpi("openram", p_str))
		result = ExtraActionType_openram;
	else if (!strcmpi("opendisk", p_str))
		result = ExtraActionType_opendisk;
	else if (!strcmpi("close", p_str))
		result = ExtraActionType_close;
	else if (!strcmpi("start", p_str))
		result = ExtraActionType_start;
	else if (!strcmpi("stop", p_str))
		result = ExtraActionType_stop;
	else if (!strcmpi("run", p_str))
		result = ExtraActionType_run;
	else if (!strcmpi("exit", p_str))
		result = ExtraActionType_exit;
	else if (!strcmpi("enable", p_str))
		result = ExtraActionType_enable;
	else if (!strcmpi("disable", p_str))
		result = ExtraActionType_disable;
	else if (!strcmpi("notify", p_str))
		result = ExtraActionType_notify;

	return result;
}

// FUNCTION: LEGO1 0x1003eae0
void ConvertHSVToRGB(float h, float s, float v, float* r_out, float* b_out, float* g_out)
{
	double calc;
	double p;
	MxLong hue_index;
	double v9;
	double v12;
	double v13;

	double s_dbl = s;

	if (s > 0.5f)
		calc = (1.0f - v) * s + v;
	else
		calc = (v + 1.0) * s_dbl;
	if (calc <= 0.0) {
		*g_out = 0.0f;
		*b_out = 0.0f;
		*r_out = 0.0f;
		return;
	}
	p = s * 2.0f - calc;
	hue_index = h * 6.0;
	v9 = (h * 6.0 - (float) hue_index) * ((calc - p) / calc) * calc;
	v12 = p + v9;
	v13 = calc - v9;
	switch (hue_index) {
	case 0:
		*r_out = calc;
		*b_out = v12;
		*g_out = p;
		break;
	case 1:
		*r_out = v13;
		*b_out = calc;
		*g_out = p;
		break;
	case 2:
		*r_out = p;
		*b_out = calc;
		*g_out = v12;
		break;
	case 3:
		*r_out = p;
		*b_out = v13;
		*g_out = calc;
		break;
	case 4:
		*r_out = v12;
		*b_out = p;
		*g_out = calc;
		break;
	case 5:
		*r_out = calc;
		*b_out = p;
		*g_out = v13;
		break;
	case 6:
		*r_out = calc;
		*b_out = p;
		*g_out = v13;
		break;
	default:
		return;
	}
}

// STUB: LEGO1 0x1003ee00
void FUN_1003ee00(MxAtomId& p_atomId, MxS32 p_id)
{
}

// FUNCTION: LEGO1 0x1003ef40
void SetAppCursor(WPARAM p_wparam)
{
	PostMessageA(MxOmni::GetInstance()->GetWindowHandle(), 0x5400, p_wparam, 0);
}
