#ifndef MXMEDIAPRESENTER_H
#define MXMEDIAPRESENTER_H

#include "decomp.h"
#include "mxdssubscriber.h"
#include "mxpresenter.h"
#include "mxstreamchunklist.h"

// VTABLE: LEGO1 0x100d4cd8
// SIZE 0x50
class MxMediaPresenter : public MxPresenter {
public:
	inline MxMediaPresenter() { Init(); }
	virtual ~MxMediaPresenter() override;

	virtual MxResult Tickle() override; // vtable+0x8

	// FUNCTION: LEGO1 0x1000c5c0
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f074c
		return "MxMediaPresenter";
	}

	// FUNCTION: LEGO1 0x1000c5d0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxMediaPresenter::ClassName()) || MxPresenter::IsA(p_name);
	}

	virtual void StreamingTickle() override;                                 // vtable+0x20
	virtual void RepeatingTickle() override;                                 // vtable+0x24
	virtual void DoneTickle() override;                                      // vtable+0x2c
	virtual void Destroy() override;                                         // vtable+0x38
	virtual MxResult StartAction(MxStreamController*, MxDSAction*) override; // vtable+0x3c
	virtual void EndAction() override;                                       // vtable+0x40
	virtual void Enable(MxBool p_enable) override;                           // vtable+0x54
	virtual void AppendChunk(MxStreamChunk* p_chunk);                        // vtable+0x58

protected:
	MxDSSubscriber* m_subscriber;      // 0x40
	MxStreamChunkList* m_chunks;       // 0x44
	MxStreamChunkListCursor* m_cursor; // 0x48
	MxStreamChunk* m_currentChunk;     // 0x4c

	void Init();
	void Destroy(MxBool p_fromDestructor);

public:
	MxStreamChunk* FUN_100b5650();
	MxStreamChunk* NextChunk();
};

// SYNTHETIC: LEGO1 0x100b46e0
// MxStreamChunkListCursor::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100b4750
// MxListCursor<MxStreamChunk *>::~MxListCursor<MxStreamChunk *>

// SYNTHETIC: LEGO1 0x100b47a0
// MxListCursor<MxStreamChunk *>::`scalar deleting destructor'

// FUNCTION: LEGO1 0x100b4810
// MxStreamChunkListCursor::~MxStreamChunkListCursor

#endif // MXMEDIAPRESENTER_H
