#ifndef MXDSFILE_H
#define MXDSFILE_H

#include "mxdssource.h"
#include "mxioinfo.h"
#include "mxstring.h"
#include "mxtypes.h"

#include <windows.h>

// VTABLE: LEGO1 0x100dc890
class MxDSFile : public MxDSSource {
public:
	__declspec(dllexport) MxDSFile(const char* p_filename, MxULong p_skipReadingChunks);
	__declspec(dllexport) virtual ~MxDSFile(); // vtable+0x0

	// FUNCTION: LEGO1 0x100c0120
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x10102594
		return "MxDSFile";
	}

	// FUNCTION: LEGO1 0x100c0130
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxDSFile::ClassName()) || MxDSSource::IsA(p_name);
	}

	__declspec(dllexport) virtual MxLong Open(MxULong);                   // vtable+0x14
	__declspec(dllexport) virtual MxLong Close();                         // vtable+0x18
	__declspec(dllexport) virtual MxResult Read(unsigned char*, MxULong); // vtable+0x20
	__declspec(dllexport) virtual MxLong Seek(MxLong, int);               // vtable+0x24
	__declspec(dllexport) virtual MxULong GetBufferSize();                // vtable+0x28
	__declspec(dllexport) virtual MxULong GetStreamBuffersNum();          // vtable+0x2c

	inline void SetFileName(const char* p_filename) { m_filename = p_filename; }

	inline MxS32 CalcFileSize() { return GetFileSize(m_io.m_info.hmmio, NULL); }

private:
	MxLong ReadChunks();
	struct ChunkHeader {
		ChunkHeader() : m_majorVersion(0), m_minorVersion(0), m_bufferSize(0), m_streamBuffersNum(0) {}

		MxU16 m_majorVersion;
		MxU16 m_minorVersion;
		MxULong m_bufferSize;
		MxS16 m_streamBuffersNum;
		MxS16 m_reserved;
	};

	MxString m_filename;
	MXIOINFO m_io;
	ChunkHeader m_header;

	// If false, read chunks immediately on open, otherwise
	// skip reading chunks until ReadChunks is explicitly called.
	MxULong m_skipReadingChunks;
};

#endif // MXDSFILE_H
