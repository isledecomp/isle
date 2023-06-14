#include "mxomnicreateparam.h"

MxOmniCreateParam::MxOmniCreateParam(const char *mediaPath, HWND windowHandle, MxVideoParam &vparam, MxOmniCreateFlags flags)
{
  this->m_mediaPath = mediaPath;
  this->m_windowHandle = windowHandle;
  this->m_videoParam = vparam;
  this->m_createFlags = flags;
}
