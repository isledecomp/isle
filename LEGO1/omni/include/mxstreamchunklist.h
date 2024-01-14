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

	// FUNCTION: LEGO1 0x100b5900
	virtual MxS8 Compare(MxStreamChunk* p_a, MxStreamChunk* p_b) override
	{
		return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
	} // vtable+0x14

	// FUNCTION: LEGO1 0x100b5920
	static void Destroy(MxStreamChunk* p_chunk) { delete p_chunk; }
};

// VTABLE: LEGO1 0x100dc510
// SIZE 0x10
class MxStreamChunkListCursor : public MxListCursor<MxStreamChunk*> {
public:
	MxStreamChunkListCursor(MxStreamChunkList* p_list) : MxListCursor<MxStreamChunk*>(p_list){};
};

// VTABLE: LEGO1 0x100dc528
// class MxListCursor<MxStreamChunk *>

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

#endif // MXSTREAMCHUNKLIST_H
