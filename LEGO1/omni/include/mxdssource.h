#ifndef MXDSSOURCE_H
#define MXDSSOURCE_H

#include "mxcore.h"
#include "mxdsbuffer.h"

// VTABLE: LEGO1 0x100dc8c8
// VTABLE: BETA10 0x101c2450
// SIZE 0x14
class MxDSSource : public MxCore {
public:
	MxDSSource() : m_lengthInDWords(0), m_pBuffer(NULL), m_position(-1) {}

	// FUNCTION: LEGO1 0x100bff60
	~MxDSSource() override { delete[] m_pBuffer; }

	// FUNCTION: LEGO1 0x100c0010
	// FUNCTION: BETA10 0x10148cc0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x10102588
		return "MxDSSource";
	}

	// FUNCTION: LEGO1 0x100c0020
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxDSSource::ClassName()) || MxCore::IsA(p_name);
	}

	virtual MxLong Open(MxULong) = 0; // vtable+0x14
	virtual MxLong Close() = 0;       // vtable+0x18

	// FUNCTION: LEGO1 0x100bffd0
	virtual MxResult ReadToBuffer(MxDSBuffer* p_buffer)
	{
		return Read(p_buffer->GetBuffer(), p_buffer->GetWriteOffset());
	} // vtable+0x1c

	virtual MxResult Read(unsigned char*, MxULong) = 0; // vtable+0x20
	virtual MxLong Seek(MxLong, MxS32) = 0;             // vtable+0x24
	virtual MxULong GetBufferSize() = 0;                // vtable+0x28
	virtual MxULong GetStreamBuffersNum() = 0;          // vtable+0x2c

	// FUNCTION: LEGO1 0x100bfff0
	virtual MxLong GetLengthInDWords() { return m_lengthInDWords; } // vtable+0x30

	// FUNCTION: LEGO1 0x100c0000
	virtual MxU32* GetBuffer() { return m_pBuffer; } // vtable+0x34

	MxLong GetPosition() const { return m_position; }

protected:
	MxULong m_lengthInDWords; // 0x08
	MxU32* m_pBuffer;         // 0x0c
	MxLong m_position;        // 0x10
};

// SYNTHETIC: LEGO1 0x100c00a0
// MxDSSource::`scalar deleting destructor'

#endif // MXDSSOURCE_H
