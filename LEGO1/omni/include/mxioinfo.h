#ifndef MXIOINFO_H
#define MXIOINFO_H

#include "mxtypes.h"

// mmsystem.h requires inclusion of windows.h before
// clang-format off
#include <windows.h>
#include <mmsystem.h>
// clang-format on

// SIZE 0x48
class MXIOINFO {
public:
	MXIOINFO();
	~MXIOINFO();

	MxU16 Open(const char*, MxULong);
	MxU16 Close(MxLong);
	MxLong Read(void*, MxLong);
	MxLong Seek(MxLong, MxLong);
	MxU16 SetBuffer(char*, MxLong, MxLong);
	MxU16 Flush(MxU16);
	MxU16 Advance(MxU16);
	MxU16 Descend(MMCKINFO*, const MMCKINFO*, MxU16);

	// NOTE: In MXIOINFO, the `hmmio` member of MMIOINFO is used like
	// an HFILE (int) instead of an HMMIO (WORD).
	MMIOINFO m_info;
};

#endif // MXIOINFO_H
