#ifndef MXOMNICREATEPARAM_H
#define MXOMNICREATEPARAM_H

#include <Windows.h>

#include "mxomnicreateflags.h"
#include "mxstring.h"
#include "mxvideoparam.h"

class MxOmniCreateParam
{
public:
  __declspec(dllexport) MxOmniCreateParam(const char *mediaPath, struct HWND__ *windowHandle, MxVideoParam &vparam, MxOmniCreateFlags flags);

  virtual void vtable00();

private:
  MxString m_mediaPath;
  HWND m_windowHandle;
  MxVideoParam m_videoParam;
  MxOmniCreateFlags m_createFlags;

};

#endif // MXOMNICREATEPARAM_H
