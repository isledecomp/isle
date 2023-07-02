#include "legoutil.h"

// OFFSET: LEGO1 0x1003eae0
void ConvertHSVToRGB(float h, float s, float v, float *r_out, float *b_out, float *g_out)
{
  double calc;
  double p;
  long hue_index;
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