#ifndef MXSTREAMCHUNKLIST_H
#define MXSTREAMCHUNKLIST_H

#include "decomp.h"
#include "mxlist.h"

class MxStreamChunk;

// VTABLE 0x100dc5d0 TEMPLATE
// class MxCollection<MxStreamChunk *>

// VTABLE 0x100dc5e8 TEMPLATE
// class MxList<MxStreamChunk *>

// VTABLE 0x100dc600
// SIZE 0x18
class MxStreamChunkList : public MxList<MxStreamChunk*> {
public:
	MxStreamChunkList() { m_customDestructor = Destroy; }

	virtual MxS8 Compare(MxStreamChunk*, MxStreamChunk*) override; // vtable+0x14

	static void Destroy(MxStreamChunk* p_chunk);
};

typedef MxListCursorChild<MxStreamChunk*> MxStreamChunkListCursor;

#endif // MXSTREAMCHUNKLIST_H
