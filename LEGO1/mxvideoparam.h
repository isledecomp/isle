#ifndef MXVIDEOPARAM_H
#define MXVIDEOPARAM_H

#include "mxpalette.h"
#include "mxrect32.h"
#include "mxvariabletable.h"
#include "mxvideoparamflags.h"

class MxVideoParam
{
public:
  __declspec(dllexport) MxVideoParam();
  __declspec(dllexport) MxVideoParam(MxVideoParam &);
  __declspec(dllexport) MxVideoParam(MxRect32 &rect, MxPalette *pal, unsigned long p3, MxVideoParamFlags &flags);
  __declspec(dllexport) MxVideoParam &operator=(const MxVideoParam &);
  __declspec(dllexport) ~MxVideoParam();

  __declspec(dllexport) void SetDeviceName(char *id);

  inline MxVideoParamFlags &flags() { return m_flags; }

private:
  MxRect32 m_rect;
  MxPalette *m_palette;
  unsigned int m_backBuffers;
  MxVideoParamFlags m_flags;
  int m_unk1c;
  char *m_deviceId;
};

#endif // MXVIDEOPARAM_H
