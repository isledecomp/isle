#ifndef MXVIDEOMANAGER_H
#define MXVIDEOMANAGER_H

#include "mxunknown100dc6b0.h"
#include "mxvideoparam.h"

// VTABLE 0x100dc810
// SIZE 0x64
class MxVideoManager : public MxUnknown100dc6b0
{
public:
  virtual ~MxVideoManager();

  virtual long Tickle(); // vtable+0x8

  __declspec(dllexport) void InvalidateRect(MxRect32 &);
  __declspec(dllexport) virtual long RealizePalette(MxPalette *); // vtable+0x30

  MxVideoManager();

  int Init();

  inline MxVideoParam& GetVideoParam() { return this->m_videoParam; }

private:
  MxVideoParam m_videoParam;
  int m_unk50;
  LPDIRECTDRAWSURFACE m_unk54;
  void* m_unk58;
  int m_unk5c;
  MxBool m_unk60;
};

#endif // MXVIDEOMANAGER_H
