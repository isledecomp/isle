#ifndef MXCOMPOSITEPRESENTER_H
#define MXCOMPOSITEPRESENTER_H

#include "mxpresenter.h"
#include "mxstl/stlcompat.h"

class MxCompositePresenterList : public list<MxPresenter*> {};

// VTABLE: LEGO1 0x100dc618
// SIZE 0x4c
class MxCompositePresenter : public MxPresenter {
public:
	MxCompositePresenter();
	virtual ~MxCompositePresenter() override; // vtable+0x0

	virtual MxLong Notify(MxParam& p) override; // vtable+0x04

	// FUNCTION: LEGO1 0x100b6210
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x100f0774
		return "MxCompositePresenter";
	}

	// FUNCTION: LEGO1 0x100b6220
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxCompositePresenter::ClassName()) || MxPresenter::IsA(name);
	}

	virtual MxResult StartAction(MxStreamController*, MxDSAction* p_action) override; // vtable+0x3c
	virtual void EndAction() override;                                                // vtable+0x40
	virtual void SetTickleState(TickleState p_tickleState) override;                  // vtable+0x44
	virtual MxBool HasTickleStatePassed(TickleState p_tickleState) override;          // vtable+0x48
	virtual void Enable(MxBool p_enable) override;                                    // vtable+0x54
	virtual void VTable0x58(MxParam& p);                                              // vtable+0x58
	virtual void VTable0x5c(MxParam& p);                                              // vtable+0x5c
	virtual void VTable0x60(MxPresenter* p_presenter);                                // vtable+0x60
	virtual MxBool VTable0x64(undefined4 p_unknown);                                  // vtable+0x64

private:
	MxCompositePresenterList m_list; // 0x40
};

// TEMPLATE: LEGO1 0x1004ae90
// list<MxPresenter *,allocator<MxPresenter *> >::_Buynode

// TEMPLATE: LEGO1 0x100b61a0
// list<MxPresenter *,allocator<MxPresenter *> >::~list<MxPresenter *,allocator<MxPresenter *> >

// SYNTHETIC: LEGO1 0x100b62d0
// MxCompositePresenter::`scalar deleting destructor'

// FUNCTION: LEGO1 0x100b62f0
// MxCompositePresenterList::~MxCompositePresenterList

// TEMPLATE: LEGO1 0x100b6340
// List<MxPresenter *>::~List<MxPresenter *>

#endif // MXCOMPOSITEPRESENTER_H
