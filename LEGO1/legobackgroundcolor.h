#ifndef LEGOBACKGROUNDCOLOR_H
#define LEGOBACKGROUNDCOLOR_H
#include "mxstring.h"
#include "mxcore.h"
#include "mxstringvariable.h"

class LegoBackgroundColor : public MxStringVariable
{
public:
  __declspec(dllexport) LegoBackgroundColor(const char *, const char *);
  void SetColorString(const char *colorString);
protected:
  float h;
  float s;
  float v;
};

#endif // LEGOBACKGROUNDCOLOR_H
