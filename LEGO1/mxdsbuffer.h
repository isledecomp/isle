#ifndef MXDSBUFFER_H
#define MXDSBUFFER_H

#include "decomp.h"
#include "mxcore.h"

class MxStreamController;
class MxDSAction;
class MxDSStreamingAction;
class MxStreamChunk;

enum MxDSBufferType {
	MxDSBufferType_Chunk = 0,
	MxDSBufferType_Allocate = 1,
	MxDSBufferType_Preallocated = 2,
	MxDSBufferType_Unknown = 3,
};

// VTABLE: LEGO1 0x100dcca0
// SIZE 0x34
class MxDSBuffer : public MxCore {
public:
	MxDSBuffer();
	virtual ~MxDSBuffer() override;

	// FUNCTION: LEGO1 0x100c6500
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x100f0568
		return "MxDSBuffer";
	}

	MxResult AllocateBuffer(MxU32 p_bufferSize, MxDSBufferType p_mode);
	MxResult SetBufferPointer(MxU32* p_buffer, MxU32 p_size);
	MxResult CreateObject(MxStreamController* p_controller, MxU32* p_data, MxDSAction* p_action, undefined4);
	MxResult StartPresenterFromAction(MxStreamController* p_controller, MxDSAction* p_action1, MxDSAction* p_action2);
	MxResult ParseChunk(MxStreamController* p_controller, MxU32* p_data, MxDSAction* p_action, MxStreamChunk* p_header);
	MxCore* ReadChunk(MxU32* p_chunkData, MxU16 p_flags);
	MxResult FUN_100c67b0(MxStreamController* p_controller, MxDSAction* p_action, undefined4*);
	void FUN_100c6f80(MxU32 p_writeOffset);

	inline MxU8* GetBuffer() { return m_pBuffer; }
	inline MxU32 GetWriteOffset() { return m_writeOffset; }

private:
	MxU8* m_pBuffer;
	MxU8* m_pIntoBuffer;
	MxU8* m_pIntoBuffer2;
	undefined4 m_unk0x14;
	undefined4 m_unk0x18;
	undefined4 m_unk0x1c;
	undefined2 m_unk0x20;
	MxDSBufferType m_mode;
	MxU32 m_writeOffset;
	MxU32 m_bytesRemaining;
	MxDSStreamingAction* m_unk0x30;
};

#endif // MXDSBUFFER_H
