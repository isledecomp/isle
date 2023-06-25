#ifndef MXBACKGROUNDCOLOR_H
#define MXACKGROUNDCOLOR_H
#include "mxstring.h"
#include "mxcore.h"
class MxBackgroundColor
{
public:
  __declspec(dllexport) MxBackgroundColor(const char *, const char *);
    MxBackgroundColor(){}
  virtual MxString* GetColorString();
  virtual void SetColorString(const char* colorString);
  virtual ~MxBackgroundColor();
protected:
  MxString m_name;
  MxString m_colorString;
};

#endif // MXBACKGROUNDCOLOR_H
