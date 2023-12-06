#ifndef MXDSSUBSCRIBER_H
#define MXDSSUBSCRIBER_H

#include "decomp.h"
#include "mxcore.h"
#include "mxdschunk.h"
#include "mxstreamchunk.h"

class MxStreamController;

// VTABLE: LEGO1 0x100dc698
// SIZE 0x4c
class MxDSSubscriber : public MxCore {
public:
	MxDSSubscriber();
	virtual ~MxDSSubscriber() override;

	// FUNCTION: LEGO1 0x100b7d50
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x101020f8
		return "MxDSSubscriber";
	}

	// FUNCTION: LEGO1 0x100b7d60
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxDSSubscriber::ClassName()) || MxCore::IsA(name);
	}

	MxResult FUN_100b7ed0(MxStreamController*, MxU32, MxS16);
	MxStreamChunk* FUN_100b8250();
	MxStreamChunk* FUN_100b8360();
	void FUN_100b8390(MxStreamChunk*);

private:
	undefined m_pad[0x44]; // 0x8
};

#endif // MXDSSUBSCRIBER_H
