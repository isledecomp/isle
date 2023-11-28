#include "mxstreamchunklist.h"

#include "mxstreamchunk.h"

DECOMP_SIZE_ASSERT(MxStreamChunkList, 0x18);
DECOMP_SIZE_ASSERT(MxStreamChunkListCursor, 0x10);

// FUNCTION: LEGO1 0x100b5900
MxS8 MxStreamChunkList::Compare(MxStreamChunk* p_a, MxStreamChunk* p_b)
{
	return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
}

// FUNCTION: LEGO1 0x100b5920
void MxStreamChunkList::Destroy(MxStreamChunk* p_chunk)
{
	if (p_chunk)
		delete p_chunk;
}

// FUNCTION: LEGO1 0x100b5930 SYNTHETIC
// MxCollection<MxStreamChunk *>::Compare

// FUNCTION: LEGO1 0x100b5990 SYNTHETIC
// MxCollection<MxStreamChunk *>::Destroy

// FUNCTION: LEGO1 0x100b59a0 SYNTHETIC
// MxList<MxStreamChunk *>::~MxList<MxStreamChunk *>

// FUNCTION: LEGO1 0x100b5aa0 SYNTHETIC
// MxCollection<MxStreamChunk *>::`scalar deleting destructor'

// FUNCTION: LEGO1 0x100b5b10 SYNTHETIC
// MxList<MxStreamChunk *>::`scalar deleting destructor'
