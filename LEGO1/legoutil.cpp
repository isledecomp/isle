#include "legoutil.h"

// OFFSET: LEGO1 0x1003eae0
void ConvertColor(float h, float s, float v, float *r_out, float *b_out, float *g_out)
{
  double calc; // st7
  double v11;
  int hue_index;
  double v9;
  double v12;
  double v13;
  if (s >= 0.5)
    calc = (1.0 - v) * s + v;
  else
    calc = (v + 1.0) * s;
  if (calc <= 0.0)
  {
    *g_out = 0.0;
    *b_out = 0.0;
    *r_out = 0.0;
    return;
  }
  v11 = s * 2.0 - calc;
  hue_index = h * 6.0;
  v9 = (h * 6.0 - (float)hue_index) * ((calc - v11) / calc) * calc;
  v12 = v11 + v9;
  v13 = calc - v9;
  switch (hue_index)
  {
  case 0:
    *r_out = calc;
    *b_out = v12;
    *g_out = v11;
    break;
  case 1:
    *r_out = v13;
    *b_out = calc;
    *g_out = v11;
    break;
  case 2:
    *r_out = v11;
    *b_out = calc;
    *g_out = v12;
    break;
  case 3:
    *r_out = v11;
    *b_out = v13;
    *g_out = calc;
    break;
  case 4:
    *r_out = v12;
    *b_out = v11;
    *g_out = calc;
    break;
  case 5:
    *r_out = calc;
    *b_out = v11;
    *g_out = v13;
    break;
  case 6:
    *r_out = calc;
    *b_out = v11;
    *g_out = v13;
    break;
  default:
    return;
  }
}