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
void ConvertHSVToRGB(float p_h, float p_s, float p_v, float* p_rOut, float* p_bOut, float* p_gOut)
{
	double calc;
	double p;
	MxLong hueIndex;
	double v9;
	double v12;
	double v13;

	double sDbl = p_s;

	if (p_s > 0.5f)
		calc = (1.0f - p_v) * p_s + p_v;
	else
		calc = (p_v + 1.0) * sDbl;
	if (calc <= 0.0) {
		*p_gOut = 0.0f;
		*p_bOut = 0.0f;
		*p_rOut = 0.0f;
		return;
	}
	p = p_s * 2.0f - calc;
	hueIndex = p_h * 6.0;
	v9 = (p_h * 6.0 - (float) hueIndex) * ((calc - p) / calc) * calc;
	v12 = p + v9;
	v13 = calc - v9;
	switch (hueIndex) {
	case 0:
		*p_rOut = calc;
		*p_bOut = v12;
		*p_gOut = p;
		break;
	case 1:
		*p_rOut = v13;
		*p_bOut = calc;
		*p_gOut = p;
		break;
	case 2:
		*p_rOut = p;
		*p_bOut = calc;
		*p_gOut = v12;
		break;
	case 3:
		*p_rOut = p;
		*p_bOut = v13;
		*p_gOut = calc;
		break;
	case 4:
		*p_rOut = v12;
		*p_bOut = p;
		*p_gOut = calc;
		break;
	case 5:
		*p_rOut = calc;
		*p_bOut = p;
		*p_gOut = v13;
		break;
	case 6:
		*p_rOut = calc;
		*p_bOut = p;
		*p_gOut = v13;
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
