#ifndef MXSTREAMCHUNKLIST_H
#define MXSTREAMCHUNKLIST_H

#include "decomp.h"
#include "mxlist.h"

class MxStreamChunk;

// VTABLE 0x100dc600
// SIZE 0x18
class MxStreamChunkList : public MxList<MxStreamChunk*> {
public:
	MxStreamChunkList() { m_customDestructor = Destroy; }

	virtual MxS8 Compare(MxStreamChunk*, MxStreamChunk*) override; // +0x14

	static void Destroy(MxStreamChunk* p_chunk);
};

typedef MxListCursorChild<MxStreamChunk*> MxStreamChunkListCursor;

// OFFSET: LEGO1 0x100b5930 TEMPLATE
// MxListParent<MxStreamChunk *>::Compare

// OFFSET: LEGO1 0x100b5990 TEMPLATE
// MxListParent<MxStreamChunk *>::Destroy

// OFFSET: LEGO1 0x100b59a0 TEMPLATE
// MxList<MxStreamChunk *>::~MxList<MxStreamChunk *>

// OFFSET: LEGO1 0x100b5b10 TEMPLATE
// MxList<MxStreamChunk *>::`scalar deleting destructor'

#endif // MXSTREAMCHUNKLIST_H
