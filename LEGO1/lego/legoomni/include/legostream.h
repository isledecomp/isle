#ifndef LEGOSTREAM_H
#define LEGOSTREAM_H

#include "compat.h"
#include "decomp.h"
#include "mxstring.h"
#include "mxtypes.h"

#pragma warning(disable : 4237)
#include <iosfwd>

#define LEGOSTREAM_MODE_READ 1
#define LEGOSTREAM_MODE_WRITE 2

class MxVariableTable;

// VTABLE: LEGO1 0x100d7d80
class LegoStream {
public:
	LegoStream() : m_mode(0) {}
	// FUNCTION: LEGO1 0x10045ad0
	inline virtual ~LegoStream() {}

	virtual MxResult Read(void* p_buffer, MxU32 p_size) = 0;
	virtual MxResult Write(const void* p_buffer, MxU32 p_size) = 0;
	virtual MxResult Tell(MxU32* p_offset) = 0;
	virtual MxResult Seek(MxU32 p_offset) = 0;

	virtual MxBool IsWriteMode();
	virtual MxBool IsReadMode();

	enum OpenFlags {
		c_readBit = 1,
		c_writeBit = 2,
		c_binaryBit = 4,
	};

	static MxResult __stdcall WriteVariable(LegoStream* p_stream, MxVariableTable* p_from, const char* p_variableName);
	static MxS32 __stdcall ReadVariable(LegoStream* p_stream, MxVariableTable* p_to);

protected:
	MxU8 m_mode;
};

// SYNTHETIC: LEGO1 0x10045b00
// LegoStream::`scalar deleting destructor'

// VTABLE: LEGO1 0x100db730
class LegoFileStream : public LegoStream {
public:
	LegoFileStream();
	virtual ~LegoFileStream() override;

	MxResult Read(void* p_buffer, MxU32 p_size) override;
	MxResult Write(const void* p_buffer, MxU32 p_size) override;
	MxResult Tell(MxU32* p_offset) override;
	MxResult Seek(MxU32 p_offset) override;

	MxResult Open(const char* p_filename, OpenFlags p_mode);

	LegoFileStream* FUN_10006030(MxString p_str);

private:
	FILE* m_hFile;
};

// SYNTHETIC: LEGO1 0x10099230
// LegoFileStream::`scalar deleting destructor'

// VTABLE: LEGO1 0x100db710
class LegoMemoryStream : public LegoStream {
public:
	LegoMemoryStream(char* p_buffer);

	MxResult Read(void* p_buffer, MxU32 p_size) override;
	MxResult Write(const void* p_buffer, MxU32 p_size) override;
	MxResult Tell(MxU32* p_offset) override;
	MxResult Seek(MxU32 p_offset) override;

private:
	char* m_buffer;
	MxU32 m_offset;
};

// SYNTHETIC: LEGO1 0x10045a80
// LegoMemoryStream::~LegoMemoryStream

// SYNTHETIC: LEGO1 0x100990f0
// LegoMemoryStream::`scalar deleting destructor'

#endif // LEGOSTREAM_H
