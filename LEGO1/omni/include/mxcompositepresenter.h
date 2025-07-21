#ifndef MXCOMPOSITEPRESENTER_H
#define MXCOMPOSITEPRESENTER_H

#include "mxpresenter.h"
#include "mxstl/stlcompat.h"

class MxEndActionNotificationParam;
class MxNotificationParam;

class MxCompositePresenterList : public list<MxPresenter*> {};

// VTABLE: LEGO1 0x100dc618
// SIZE 0x4c
class MxCompositePresenter : public MxPresenter {
public:
	MxCompositePresenter();
	~MxCompositePresenter() override; // vtable+0x00

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: BETA10 0x1004da30
	static const char* HandlerClassName()
	{
		// STRING: LEGO1 0x100f0774
		return "MxCompositePresenter";
	}

	// FUNCTION: LEGO1 0x100b6210
	// FUNCTION: BETA10 0x1004da00
	const char* ClassName() const override // vtable+0x0c
	{
		return HandlerClassName();
	}

	// FUNCTION: LEGO1 0x100b6220
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxCompositePresenter::ClassName()) || MxPresenter::IsA(p_name);
	}

	MxResult StartAction(MxStreamController* p_controller, MxDSAction* p_action) override; // vtable+0x3c
	void EndAction() override;                                                             // vtable+0x40
	void SetTickleState(TickleState p_tickleState) override;                               // vtable+0x44
	MxBool HasTickleStatePassed(TickleState p_tickleState) override;                       // vtable+0x48
	void Enable(MxBool p_enable) override;                                                 // vtable+0x54
	virtual void HandleEndAction(MxEndActionNotificationParam& p_param);                   // vtable+0x58
	virtual void HandlePresenter(MxNotificationParam& p_param);                            // vtable+0x5c
	virtual void AdvanceSerialAction(MxPresenter* p_presenter);                            // vtable+0x60

	// FUNCTION: LEGO1 0x1000caf0
	virtual MxBool GetActionEnded(undefined4 p_undefined)
	{
		if (m_compositePresenter) {
			return m_compositePresenter->GetActionEnded(p_undefined);
		}
		return TRUE;
	} // vtable+0x64

	MxCompositePresenterList* GetList() { return &m_list; }

protected:
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

// TEMPLATE: LEGO1 0x100b6cd0
// MxList<MxDSAction *>::DeleteEntry

#endif // MXCOMPOSITEPRESENTER_H
