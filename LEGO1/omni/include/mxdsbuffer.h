#ifndef MXDSBUFFER_H
#define MXDSBUFFER_H

#include "decomp.h"
#include "mxcore.h"

class MxStreamController;
class MxDSAction;
class MxDSStreamingAction;
class MxStreamChunk;
class MxDSChunk;

// VTABLE: LEGO1 0x100dcca0
// VTABLE: BETA10 0x101c2898
// SIZE 0x34
class MxDSBuffer : public MxCore {
public:
	enum Type {
		e_chunk = 0,
		e_allocate = 1,
		e_preallocated = 2,
		e_unknown = 3,
	};

	MxDSBuffer();
	~MxDSBuffer() override;

	// FUNCTION: LEGO1 0x100c6500
	// FUNCTION: BETA10 0x10158510
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x101025b8
		return "MxDSBuffer";
	}

	MxResult AllocateBuffer(MxU32 p_bufferSize, Type p_mode);
	MxResult SetBufferPointer(MxU8* p_buffer, MxU32 p_size);
	MxResult FUN_100c67b0(
		MxStreamController* p_controller,
		MxDSAction* p_action,
		MxDSStreamingAction** p_streamingAction
	);
	MxResult CreateObject(
		MxStreamController* p_controller,
		MxU32* p_data,
		MxDSAction* p_action,
		MxDSStreamingAction** p_streamingAction
	);
	MxResult StartPresenterFromAction(MxStreamController* p_controller, MxDSAction* p_action1, MxDSAction* p_action2);
	MxResult ParseChunk(
		MxStreamController* p_controller,
		MxU32* p_data,
		MxDSAction* p_action,
		MxDSStreamingAction** p_streamingAction,
		MxStreamChunk* p_header
	);
	MxU8* SkipToData();
	MxU8 ReleaseRef(MxDSChunk*);
	void AddRef(MxDSChunk* p_chunk);
	MxResult CalcBytesRemaining(MxU8* p_data);
	void FUN_100c6f80(MxU32 p_writeOffset);
	MxU8* FUN_100c6fa0(MxU8* p_data);
	MxResult FUN_100c7090(MxDSBuffer* p_buf);

	static MxCore* ReadChunk(MxDSBuffer* p_buffer, MxU32* p_chunkData, MxU16 p_flags);
	static MxResult Append(MxU8* p_buffer1, MxU8* p_buffer2);

	// FUNCTION: BETA10 0x10148c60
	MxU8* GetBuffer() { return m_pBuffer; }

	// FUNCTION: BETA10 0x10164240
	undefined4 GetUnknown14() { return m_unk0x14; }

	// FUNCTION: BETA10 0x10156420
	MxBool HasRef() { return m_referenceCount != 0; }

	MxU16 GetRefCount() { return m_referenceCount; }
	Type GetMode() { return m_mode; }

	// FUNCTION: BETA10 0x10148c40
	MxU32 GetWriteOffset() { return m_writeOffset; }

	// FUNCTION: BETA10 0x101590d0
	MxU32 GetBytesRemaining() { return m_bytesRemaining; }

	void SetUnknown14(undefined4 p_unk0x14) { m_unk0x14 = p_unk0x14; }
	void SetUnknown1c(undefined4 p_unk0x1c) { m_unk0x1c = p_unk0x1c; }

	// FUNCTION: BETA10 0x10164260
	void SetMode(Type p_mode) { m_mode = p_mode; }

	void SetUnk30(MxDSStreamingAction* p_unk0x30) { m_unk0x30 = p_unk0x30; }

	// SYNTHETIC: LEGO1 0x100c6510
	// SYNTHETIC: BETA10 0x10158530
	// MxDSBuffer::`scalar deleting destructor'

private:
	MxU8* m_pBuffer;                // 0x08
	MxU8* m_pIntoBuffer;            // 0x0c
	MxU8* m_pIntoBuffer2;           // 0x10
	undefined4 m_unk0x14;           // 0x14
	undefined4 m_unk0x18;           // 0x18
	undefined4 m_unk0x1c;           // 0x1c
	MxU16 m_referenceCount;         // 0x20
	Type m_mode;                    // 0x24
	MxU32 m_writeOffset;            // 0x28
	MxU32 m_bytesRemaining;         // 0x2c
	MxDSStreamingAction* m_unk0x30; // 0x30
};

#endif // MXDSBUFFER_H
