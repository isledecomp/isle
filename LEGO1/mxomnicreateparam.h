#ifndef MXOMNICREATEPARAM_H
#define MXOMNICREATEPARAM_H

#include <windows.h>

#include "mxomnicreateflags.h"
#include "mxomnicreateparambase.h"
#include "mxstring.h"
#include "mxvideoparam.h"

class MxOmniCreateParam : public MxOmniCreateParamBase
{
public:
  __declspec(dllexport) MxOmniCreateParam(const char *mediaPath, struct HWND__ *windowHandle, MxVideoParam &vparam, MxOmniCreateFlags flags);

  const MxOmniCreateFlags& CreateFlags() const { return this->m_createFlags; }

private:
  MxString m_mediaPath;
  HWND m_windowHandle;
  MxVideoParam m_videoParam;
  MxOmniCreateFlags m_createFlags;
};

#endif // MXOMNICREATEPARAM_H
