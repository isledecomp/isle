#ifndef LEGOBACKGROUNDCOLOR_H
#define LEGOBACKGROUNDCOLOR_H
#include "mxstring.h"
#include "mxcore.h"
#include "mxbackgroundcolor.h"
class LegoBackgroundColor : public MxBackgroundColor
{
public:
  __declspec(dllexport) LegoBackgroundColor(const char *, const char *);
  void SetColorString(const char* colorString);
};

#endif // LEGOBACKGROUNDCOLOR_H
