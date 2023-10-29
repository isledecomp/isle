#ifndef MXDSBUFFER_H
#define MXDSBUFFER_H

#include "decomp.h"
#include "mxcore.h"

// VTABLE 0x100dcca0
// SIZE 0x34
class MxDSBuffer : public MxCore {
public:
	MxDSBuffer();
	virtual ~MxDSBuffer() override;

	// OFFSET: LEGO1 0x100c6500
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f0568
		return "MxDSBuffer";
	}

	MxResult FUN_100c6780(void* p_buffer, MxU32 p_size);
	void FUN_100c6f80(MxU32 p_unk);

	inline void* GetBuffer() { return m_pBuffer; }
	inline MxU32 GetWriteOffset() { return m_writeOffset; }

private:
	void* m_pBuffer;
	void* m_pIntoBuffer;
	void* m_pIntoBuffer2;
	undefined4 m_unk14;
	undefined4 m_unk18;
	undefined4 m_unk1c;
	undefined2 m_unk20;
	undefined4 m_mode;
	MxU32 m_writeOffset;
	MxU32 m_bytesRemaining;
	undefined4 m_unk30;
};

#endif // MXDSBUFFER_H
