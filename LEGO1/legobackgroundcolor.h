#ifndef LEGOBACKGROUNDCOLOR_H
#define LEGOBACKGROUNDCOLOR_H

#include "mxstringvariable.h"

class LegoBackgroundColor : public MxStringVariable
{
public:
  __declspec(dllexport) LegoBackgroundColor(const char *p_name, const char *p_colorString);
  void SetColorString(const char *p_colorString);

private:
  float h;
  float s;
  float v;
};

#endif // LEGOBACKGROUNDCOLOR_H
