#include "mxstreamchunklist.h"

#include "mxstreamchunk.h"

DECOMP_SIZE_ASSERT(MxStreamChunkList, 0x18);
DECOMP_SIZE_ASSERT(MxStreamChunkListCursor, 0x10);

// OFFSET: LEGO1 0x100b5900
MxS8 MxStreamChunkList::Compare(MxStreamChunk* p_a, MxStreamChunk* p_b)
{
	return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
}

// OFFSET: LEGO1 0x100b5920
void MxStreamChunkList::Destroy(MxStreamChunk* p_chunk)
{
	if (p_chunk)
		delete p_chunk;
}

// OFFSET: LEGO1 0x100b5930 TEMPLATE
// MxCollection<MxStreamChunk *>::Compare

// OFFSET: LEGO1 0x100b5990 TEMPLATE
// MxCollection<MxStreamChunk *>::Destroy

// OFFSET: LEGO1 0x100b59a0 TEMPLATE
// MxList<MxStreamChunk *>::~MxList<MxStreamChunk *>

// OFFSET: LEGO1 0x100b5aa0 TEMPLATE
// MxCollection<MxStreamChunk *>::`scalar deleting destructor'

// OFFSET: LEGO1 0x100b5b10 TEMPLATE
// MxList<MxStreamChunk *>::`scalar deleting destructor'
