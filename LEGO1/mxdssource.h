#ifndef MXDSSOURCE_H
#define MXDSSOURCE_H

#include "mxcore.h"

class MxDSBuffer;

// VTABLE: LEGO1 0x100dc8c8
class MxDSSource : public MxCore {
public:
	MxDSSource() : m_lengthInDWords(0), m_pBuffer(NULL), m_position(-1) {}

	// FUNCTION: LEGO1 0x100c0010
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x10102588
		return "MxDSSource";
	}

	// FUNCTION: LEGO1 0x100c0020
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxDSSource::ClassName()) || MxCore::IsA(p_name);
	}

	virtual MxLong Open(MxULong) = 0;
	virtual MxLong Close() = 0;
	virtual void ReadToBuffer(MxDSBuffer* p_buffer);
	virtual MxResult Read(unsigned char*, MxULong) = 0;
	virtual MxLong Seek(MxLong, int) = 0;
	virtual MxULong GetBufferSize() = 0;
	virtual MxULong GetStreamBuffersNum() = 0;
	virtual MxLong GetLengthInDWords();
	virtual MxU32* GetBuffer(); // 0x34

protected:
	MxULong m_lengthInDWords;
	MxU32* m_pBuffer;
	MxLong m_position;
};

#endif // MXDSSOURCE_H
