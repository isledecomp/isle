#include "mxdsbuffer.h"

#include "mxdschunk.h"
#include "mxdsstreamingaction.h"
#include "mxomni.h"
#include "mxstreamchunk.h"
#include "mxstreamcontroller.h"
#include "mxstreamer.h"

DECOMP_SIZE_ASSERT(MxDSBuffer, 0x34);

// FUNCTION: LEGO1 0x100c6470
MxDSBuffer::MxDSBuffer()
{
	m_refcount = 0;
	m_pBuffer = NULL;
	m_pIntoBuffer = NULL;
	m_pIntoBuffer2 = NULL;
	m_unk0x14 = 0;
	m_unk0x18 = 0;
	m_unk0x1c = 0;
	m_writeOffset = 0;
	m_bytesRemaining = 0;
	m_mode = MxDSBufferType_Preallocated;
	m_unk0x30 = 0;
}

// FUNCTION: LEGO1 0x100c6530
MxDSBuffer::~MxDSBuffer()
{
	if (m_pBuffer != NULL) {
		if (m_mode == MxDSBufferType_Chunk) {
			// TODO
		}
		else if (m_mode == MxDSBufferType_Allocate || m_mode == MxDSBufferType_Unknown) {
			delete[] m_pBuffer;
		}
	}

	m_unk0x14 = 0;
	m_unk0x1c = 0;
}

// FUNCTION: LEGO1 0x100c6640
MxResult MxDSBuffer::AllocateBuffer(MxU32 p_bufferSize, MxDSBufferType p_mode)
{
	MxResult result = FAILURE;
	MxU32 i = 0;
	if (p_mode == MxDSBufferType_Allocate) {
		m_pBuffer = new MxU8[p_bufferSize];
	}
	else if (p_mode == MxDSBufferType_Chunk) {
		MxStreamer* streamer = Streamer();
		// I have no clue as to what this does, or even if its correct. Maybe it's related to storing chunks in
		// MxDiskStreamController?
		if (p_bufferSize >> 10 == 0x40) {
			i = 0;
			while (i < 22) {
				if ((*(MxU32*) ((streamer->GetSubclass1().GetUnk08() + ((i & 0xffffffe7) >> 3)) & 1 << ((MxU8) i & 0x1f)
					)) == 0) {
					MxU32* ptr = (MxU32*) ((streamer->GetSubclass1().GetUnk08() + ((i & 0xffffffe7) >> 3)) &
										   1 << ((MxU8) i & 0x1f));

					// mark it as used?
					*ptr = *ptr ^ 1 << (i & 0x1f);

					m_pBuffer =
						(MxU8*) (streamer->GetSubclass1().GetSize() * i * 0x400 + streamer->GetSubclass1().GetBuffer());
					break;
				}
				i++;
			}

			m_pBuffer = NULL;
		}
		else if (p_bufferSize >> 10 == 0x80) {
			i = 0;
			// Same thing as above but it uses subclass2
			while (i < 22) {
				if ((*(MxU32*) ((streamer->GetSubclass2().GetUnk08() + ((i & 0xffffffe7) >> 3)) & 1 << ((MxU8) i & 0x1f)
					)) == 0) {
					MxU32* ptr = (MxU32*) ((streamer->GetSubclass2().GetUnk08() + ((i & 0xffffffe7) >> 3)) &
										   1 << ((MxU8) i & 0x1f));

					// mark it as used?
					*ptr = *ptr ^ 1 << (i & 0x1f);

					m_pBuffer =
						(MxU8*) (streamer->GetSubclass2().GetSize() * i * 0x400 + streamer->GetSubclass2().GetBuffer());
					break;
				}
				i++;
			}

			m_pBuffer = NULL;
		}
		else {
			m_pIntoBuffer = NULL;
		}
	}

	m_pIntoBuffer = m_pBuffer;
	m_pIntoBuffer2 = m_pBuffer;
	if (m_pBuffer != NULL) {
		m_mode = p_mode;
		m_bytesRemaining = p_bufferSize;
		m_writeOffset = p_bufferSize;
		result = SUCCESS;
	}
	return result;
}

// FUNCTION: LEGO1 0x100c6780
MxResult MxDSBuffer::SetBufferPointer(MxU32* p_buffer, MxU32 p_size)
{
	m_pBuffer = (MxU8*) p_buffer;
	m_pIntoBuffer = (MxU8*) p_buffer;
	m_pIntoBuffer2 = (MxU8*) p_buffer;
	m_bytesRemaining = p_size;
	m_writeOffset = p_size;
	m_mode = MxDSBufferType_Preallocated;
	return SUCCESS;
}

// STUB: LEGO1 0x100c67b0
MxResult MxDSBuffer::FUN_100c67b0(
	MxStreamController* p_controller,
	MxDSAction* p_action,
	MxDSStreamingAction** p_streamingAction
)
{
	// TODO STUB
	return FAILURE;
}

// FUNCTION: LEGO1 0x100c68a0
MxResult MxDSBuffer::CreateObject(
	MxStreamController* p_controller,
	MxU32* p_data,
	MxDSAction* p_action,
	undefined4 p_undefined
)
{
	if (p_data == NULL) {
		return FAILURE;
	}

	MxCore* header = ReadChunk(this, p_data, p_action->GetUnknown24());

	if (header == NULL) {
		return FAILURE;
	}

	if (*p_data == FOURCC('M', 'x', 'O', 'b'))
		return StartPresenterFromAction(p_controller, p_action, (MxDSAction*) header);
	else if (*p_data == FOURCC('M', 'x', 'C', 'h')) {
		MxStreamChunk* chunk = (MxStreamChunk*) header;
		if (!m_unk0x30->HasId((chunk)->GetObjectId())) {
			delete header;
			return SUCCESS;
		}

		return ParseChunk(p_controller, p_data, p_action, p_undefined, chunk);
	}

	delete header;
	return FAILURE;
}

// FUNCTION: LEGO1 0x100c6960
MxResult MxDSBuffer::StartPresenterFromAction(
	MxStreamController* p_controller,
	MxDSAction* p_action1,
	MxDSAction* p_objectheader
)
{
	if (!m_unk0x30->GetInternalAction()) {
		p_objectheader->SetAtomId(p_action1->GetAtomId());
		p_objectheader->SetUnknown28(p_action1->GetUnknown28());
		p_objectheader->SetUnknown84(p_action1->GetUnknown84());
		p_objectheader->SetOrigin(p_action1->GetOrigin());
		p_objectheader->SetUnknown90(p_action1->GetUnknown90());
		p_objectheader->MergeFrom(*p_action1);

		m_unk0x30->SetInternalAction(p_objectheader->Clone());

		p_controller->InsertActionToList54(p_objectheader);

		if (MxOmni::GetInstance()->CreatePresenter(p_controller, *p_objectheader) != SUCCESS) {
			return FAILURE;
		}

		m_unk0x30->SetLoopCount(p_objectheader->GetLoopCount());
		m_unk0x30->SetFlags(p_objectheader->GetFlags());
		m_unk0x30->SetDuration(p_objectheader->GetDuration());

		if (m_unk0x30->GetInternalAction() == NULL) {
			return FAILURE;
		}
	}
	else if (p_objectheader) {
		delete p_objectheader;
	}

	return SUCCESS;
}

// STUB: LEGO1 0x100c6a50
MxResult MxDSBuffer::ParseChunk(
	MxStreamController* p_controller,
	MxU32* p_data,
	MxDSAction* p_action,
	undefined4,
	MxStreamChunk* p_header
)
{
	// TODO
	return FAILURE;
}

// FUNCTION: LEGO1 0x100c6d00
MxCore* MxDSBuffer::ReadChunk(MxDSBuffer* p_buffer, MxU32* p_chunkData, MxU16 p_flags)
{
	// This function reads a chunk. If it is an object, this function returns an MxDSObject. If it is a chunk, returns a
	// MxDSChunk.
	MxCore* result = NULL;
	MxU8* dataStart = (MxU8*) p_chunkData + 8;

	switch (*p_chunkData) {
	case FOURCC('M', 'x', 'O', 'b'):
		result = DeserializeDSObjectDispatch(&dataStart, p_flags);
		break;
	case FOURCC('M', 'x', 'C', 'h'):
		result = new MxStreamChunk();
		if (result != NULL && ((MxStreamChunk*) result)->ReadChunk(p_buffer, (MxU8*) p_chunkData) != SUCCESS) {
			delete result;
			result = NULL;
		}
		return result;
	}

	return result;
}

// FUNCTION: LEGO1 0x100c6ec0
MxU8 MxDSBuffer::ReleaseRef(MxDSChunk*)
{
	if (m_refcount != 0) {
		m_refcount--;
	}
	return 0;
}

// FUNCTION: LEGO1 0x100c6ee0
void MxDSBuffer::AddRef(MxDSChunk* p_chunk)
{
	if (p_chunk) {
		m_refcount++;
	}
}

// FUNCTION: LEGO1 0x100c6f80
void MxDSBuffer::FUN_100c6f80(MxU32 p_writeOffset)
{
	if (p_writeOffset < m_writeOffset) {
		m_pIntoBuffer2 = m_pBuffer + p_writeOffset;
		m_pIntoBuffer = m_pBuffer + p_writeOffset;
	}
}
