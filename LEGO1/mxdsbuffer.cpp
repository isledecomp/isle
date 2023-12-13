#include "mxdsbuffer.h"

#include "mxomni.h"
#include "mxstreamcontroller.h"
#include "mxstreamer.h"

DECOMP_SIZE_ASSERT(MxDSBuffer, 0x34);

// FUNCTION: LEGO1 0x100c6470
MxDSBuffer::MxDSBuffer()
{
	m_unk0x20 = 0;
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
		// MxRamStreamController?
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
MxResult MxDSBuffer::FUN_100c67b0(MxStreamController* p_controller, MxDSAction* p_action, undefined4*)
{
	// TODO STUB
	return FAILURE;
}

// FUNCTION: LEGO1 0x100c6f80
void MxDSBuffer::FUN_100c6f80(MxU32 p_writeOffset)
{
	if (p_writeOffset < m_writeOffset) {
		m_pIntoBuffer2 = m_pBuffer + p_writeOffset;
		m_pIntoBuffer = m_pBuffer + p_writeOffset;
	}
}
