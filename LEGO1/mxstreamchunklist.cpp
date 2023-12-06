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

// TEMPLATE: LEGO1 0x100b5930
// MxCollection<MxStreamChunk *>::Compare

// TEMPLATE: LEGO1 0x100b5990
// MxCollection<MxStreamChunk *>::Destroy

// TEMPLATE: LEGO1 0x100b59a0
// MxList<MxStreamChunk *>::~MxList<MxStreamChunk *>

// SYNTHETIC: LEGO1 0x100b5aa0
// MxCollection<MxStreamChunk *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100b5b10
// MxList<MxStreamChunk *>::`scalar deleting destructor'
