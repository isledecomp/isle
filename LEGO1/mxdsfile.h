#ifndef MXDSFILE_H
#define MXDSFILE_H

#include "mxdssource.h"
#include "mxioinfo.h"
#include "mxstring.h"
#include "mxtypes.h"

// VTABLEADDR 0x100dc890
class MxDSFile : public MxDSSource {
public:
	__declspec(dllexport) MxDSFile(const char* filename, MxULong skipReadingChunks);
	__declspec(dllexport) virtual ~MxDSFile(); // vtable+0x0

	// OFFSET: LEGO1 0x100c0120
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x10102594
		return "MxDSFile";
	}

	// OFFSET: LEGO1 0x100c0130
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxDSFile::ClassName()) || MxDSSource::IsA(name);
	}

	__declspec(dllexport) virtual MxLong Open(MxULong);                   // vtable+0x14
	__declspec(dllexport) virtual MxLong Close();                         // vtable+0x18
	__declspec(dllexport) virtual MxResult Read(unsigned char*, MxULong); // vtable+0x20
	__declspec(dllexport) virtual MxLong Seek(MxLong, int);               // vtable+0x24
	__declspec(dllexport) virtual MxULong GetBufferSize();                // vtable+0x28
	__declspec(dllexport) virtual MxULong GetStreamBuffersNum();          // vtable+0x2c
private:
	MxLong ReadChunks();
	struct ChunkHeader {
		ChunkHeader() : majorVersion(0), minorVersion(0), bufferSize(0), streamBuffersNum(0) {}

		MxU16 majorVersion;
		MxU16 minorVersion;
		MxULong bufferSize;
		MxS16 streamBuffersNum;
		MxS16 reserved;
	};

	MxString m_filename;
	MXIOINFO m_io;
	ChunkHeader m_header;

	// If false, read chunks immediately on open, otherwise
	// skip reading chunks until ReadChunks is explicitly called.
	MxULong m_skipReadingChunks;
};

#endif // MXDSFILE_H
