#ifndef MXSTREAMCHUNKLIST_H
#define MXSTREAMCHUNKLIST_H

#include "decomp.h"
#include "mxlist.h"

class MxStreamChunk;

// VTABLE: LEGO1 0x100dc5d0
// class MxCollection<MxStreamChunk *>

// VTABLE: LEGO1 0x100dc5e8
// class MxList<MxStreamChunk *>

// VTABLE: LEGO1 0x100dc600
// SIZE 0x18
class MxStreamChunkList : public MxList<MxStreamChunk*> {
public:
	MxStreamChunkList() { m_customDestructor = Destroy; }

	virtual MxS8 Compare(MxStreamChunk*, MxStreamChunk*) override; // vtable+0x14

	static void Destroy(MxStreamChunk* p_chunk);
};

class MxStreamChunkListCursor : public MxListCursor<MxStreamChunk*> {
public:
	MxStreamChunkListCursor(MxStreamChunkList* p_list) : MxListCursor<MxStreamChunk*>(p_list){};
};

#endif // MXSTREAMCHUNKLIST_H
