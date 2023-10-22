#ifndef MXIOINFO_H
#define MXIOINFO_H

#include <windows.h>
#include <mmsystem.h>

#include "mxtypes.h"

class MXIOINFO
{
public:
  MXIOINFO();
  __declspec(dllexport) ~MXIOINFO();

  MxU16 Open(const char *, MxULong);
  MxU16 Close(MxLong);
  MxLong Read(void *, MxLong);
  MxResult Seek(MxLong, int);
  MxU16 SetBuffer(char *, MxLong, MxLong);
  MxU16 Flush(MxU16);
  MxU16 Advance(MxU16);
  MxU16 Descend(MMCKINFO *, const MMCKINFO *, MxU16);

  // NOTE: In MXIOINFO, the `hmmio` member of MMIOINFO is used like
  // an HFILE (int) instead of an HMMIO (WORD).
  MMIOINFO m_info;
};

#endif // MXIOINFO_H
