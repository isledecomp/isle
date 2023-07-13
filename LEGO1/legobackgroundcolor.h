#ifndef LEGOBACKGROUNDCOLOR_H
#define LEGOBACKGROUNDCOLOR_H

#include "mxvariable.h"

class LegoBackgroundColor : public MxVariable
{
public:
  __declspec(dllexport) LegoBackgroundColor(const char *p_key, const char *p_value);
  void SetValue(const char *p_colorString);

private:
  float h;
  float s;
  float v;
};

#endif // LEGOBACKGROUNDCOLOR_H
