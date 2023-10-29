#ifndef MXDSSUBSCRIBER_H
#define MXDSSUBSCRIBER_H

#include "mxcore.h"

// VTABLE 0x100dc698
// SIZE 0x4c
class MxDSSubscriber : public MxCore {
public:
	MxDSSubscriber();
	virtual ~MxDSSubscriber() override;

	// OFFSET: LEGO1 0x100b7d50
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x101020f8
		return "MxDSSubscriber";
	}

	// OFFSET: LEGO1 0x100b7d60
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxDSSubscriber::ClassName()) || MxCore::IsA(name);
	}
};

#endif // MXDSSUBSCRIBER_H
