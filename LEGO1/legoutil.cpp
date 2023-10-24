#include "legoutil.h"

#include "mxomni.h"
#include "mxtypes.h"

#include "math.h"

#include <string.h>

// OFFSET: LEGO1 0x1003e300
ExtraActionType MatchActionString(const char *p_str) {
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

// OFFSET: LEGO1 0x100a5b40
void CalcLocalTransform(const MxVector3 &p_posVec, const MxVector3 &p_dirVec,
                        const MxVector3 &p_upVec, MxMatrix &p_outMatrix)
{
  MxFloat x_axis[3], y_axis[3], z_axis[3];

  NORMVEC3(z_axis, p_dirVec)
  NORMVEC3(y_axis, p_upVec)

  VXV3(x_axis, y_axis, z_axis);

  // This is an unrolled version of the "NORMVEC3" macro,
  // used here to apply a silly hack to get a 100% match
  {
    const MxFloat axis2Operation = (x_axis)[2] * (x_axis)[2];
    MxDouble len = sqrt(((x_axis)[0] * (x_axis)[0] + axis2Operation + (x_axis)[1] * (x_axis)[1]));
    ((x_axis)[0] = (x_axis)[0] / (len), (x_axis)[1] = (x_axis)[1] / (len), (x_axis)[2] = (x_axis)[2] / (len));
  }

  VXV3(y_axis, z_axis, x_axis);

  // Exact same thing as pointed out by the above comment
  {
    const MxFloat axis2Operation = (y_axis)[2] * (y_axis)[2];
    MxDouble len = sqrt(((y_axis)[0] * (y_axis)[0] + axis2Operation + (y_axis)[1] * (y_axis)[1]));
    ((y_axis)[0] = (y_axis)[0] / (len), (y_axis)[1] = (y_axis)[1] / (len), (y_axis)[2] = (y_axis)[2] / (len));
  }

  SET4from3(&p_outMatrix[0], x_axis,    0);
  SET4from3(&p_outMatrix[4], y_axis,    0);
  SET4from3(&p_outMatrix[8], z_axis,    0);
  SET4from3(&p_outMatrix[12], p_posVec, 1);
}

// OFFSET: LEGO1 0x1003eae0
void ConvertHSVToRGB(float h, float s, float v, float *r_out, float *b_out, float *g_out)
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
  if (calc <= 0.0)
  {
    *g_out = 0.0f;
    *b_out = 0.0f;
    *r_out = 0.0f;
    return;
  }
  p = s * 2.0f - calc;
  hue_index = h * 6.0;
  v9 = (h * 6.0 - (float)hue_index) * ((calc - p) / calc) * calc;
  v12 = p + v9;
  v13 = calc - v9;
  switch (hue_index)
  {
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

// OFFSET: LEGO1 0x1003ef40
void SetAppCursor(WPARAM p_wparam)
{
  PostMessageA(MxOmni::GetInstance()->GetWindowHandle(), 0x5400, p_wparam, 0);
}
