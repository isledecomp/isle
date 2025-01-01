#ifndef MXIO_H
#define MXIO_H

#include "mxtypes.h"

// mmsystem.h requires inclusion of windows.h before
// clang-format off
#include <windows.h>
#include <mmsystem.h>
// clang-format on

#if defined(_M_IX86) || defined(__i386__)
#define MXIO_MINFO_MFILE
#endif

// SIZE 0x48
class MXIOINFO {
public:
	MXIOINFO();
	~MXIOINFO();

	MxU16 Open(const char*, MxULong);
	MxU16 Close(MxLong);
	MxLong Read(void*, MxLong);
	MxLong Write(void*, MxLong);
	MxLong Seek(MxLong, MxLong);
	MxU16 SetBuffer(char*, MxLong, MxLong);
	MxU16 Flush(MxU16);
	MxU16 Advance(MxU16);
	MxU16 Descend(MMCKINFO*, const MMCKINFO*, MxU16);
	MxU16 Ascend(MMCKINFO*, MxU16);
	MxU16 CreateChunk(MMCKINFO* p_chunkInfo, MxU16 p_create);

	// NOTE: In MXIOINFO, the `hmmio` member of MMIOINFO is used like
	// an HFILE (int) instead of an HMMIO (WORD).
	MMIOINFO m_info;
#ifndef MXIO_MINFO_MFILE
	HFILE m_file;
#endif
};

#endif // MXIO_H
