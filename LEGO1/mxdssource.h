#ifndef MXDSSOURCE_H
#define MXDSSOURCE_H

#include "mxcore.h"

class MxDSBuffer;

// VTABLE: LEGO1 0x100dc8c8
// SIZE 0x14
class MxDSSource : public MxCore {
public:
	MxDSSource() : m_lengthInDWords(0), m_pBuffer(NULL), m_position(-1) {}

	// FUNCTION: LEGO1 0x100c0010
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x10102588
		return "MxDSSource";
	}

	// FUNCTION: LEGO1 0x100c0020
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxDSSource::ClassName()) || MxCore::IsA(p_name);
	}

	virtual MxLong Open(MxULong) = 0;                    // vtable+0x14
	virtual MxLong Close() = 0;                          // vtable+0x18
	virtual MxResult ReadToBuffer(MxDSBuffer* p_buffer); // vtable+0x1c
	virtual MxResult Read(unsigned char*, MxULong) = 0;  // vtable+0x20
	virtual MxLong Seek(MxLong, int) = 0;                // vtable+0x24
	virtual MxULong GetBufferSize() = 0;                 // vtable+0x28
	virtual MxULong GetStreamBuffersNum() = 0;           // vtable+0x2c
	virtual MxLong GetLengthInDWords();                  // vtable+0x30
	virtual MxU32* GetBuffer();                          // vtable+0x34
	inline MxLong GetPosition() const { return m_position; }

protected:
	MxULong m_lengthInDWords; // 0x08
	MxU32* m_pBuffer;         // 0x0c
	MxLong m_position;        // 0x10
};

#endif // MXDSSOURCE_H
