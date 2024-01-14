#ifndef MXPRESENTER_H
#define MXPRESENTER_H

#include "decomp.h"
#include "mxcore.h"
#include "mxcriticalsection.h"
#include "mxdsaction.h"
#include "mxomni.h"
#include "mxpoint32.h"

class MxCompositePresenter;
class MxStreamController;
class MxEntity;

// VTABLE: LEGO1 0x100d4d38
// SIZE 0x40
class MxPresenter : public MxCore {
public:
	enum TickleState {
		TickleState_Idle = 0,
		TickleState_Ready,
		TickleState_Starting,
		TickleState_Streaming,
		TickleState_Repeating,
		TickleState_unk5,
		TickleState_Done,
	};

	MxPresenter() { Init(); }

#ifdef ISLE_APP
	__declspec(dllexport) virtual ~MxPresenter() override; // vtable+0x00
#else
	// FUNCTION: LEGO1 0x1000bf00
	__declspec(dllexport) virtual ~MxPresenter() override{}; // vtable+0x00
#endif

	__declspec(dllexport) virtual MxResult Tickle() override; // vtable+0x08

	// FUNCTION: LEGO1 0x1000bfe0
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f0740
		return "MxPresenter";
	}

	// FUNCTION: LEGO1 0x1000bff0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxPresenter::ClassName()) || MxCore::IsA(p_name);
	}

	// FUNCTION: LEGO1 0x1000be30
	virtual void VTable0x14() {} // vtable+0x14

	// FUNCTION: LEGO1 0x1000be40
	virtual void ReadyTickle()
	{
		ParseExtra();
		ProgressTickleState(TickleState_Starting);
	} // vtable+0x18

	// FUNCTION: LEGO1 0x1000be60
	virtual void StartingTickle() { ProgressTickleState(TickleState_Streaming); } // vtable+0x1c

	// FUNCTION: LEGO1 0x1000be80
	virtual void StreamingTickle() { ProgressTickleState(TickleState_Repeating); }; // vtable+0x20

	// FUNCTION: LEGO1 0x1000bea0
	virtual void RepeatingTickle() { ProgressTickleState(TickleState_unk5); }; // vtable+0x24

	// FUNCTION: LEGO1 0x1000bec0
	virtual void Unk5Tickle() { ProgressTickleState(TickleState_Done); }; // vtable+0x28

protected:
#ifdef ISLE_APP
	__declspec(dllexport) virtual void DoneTickle(); // vtable+0x2c
#else
	// FUNCTION: LEGO1 0x1000bee0
	__declspec(dllexport) virtual void DoneTickle() { ProgressTickleState(TickleState_Idle); }; // vtable+0x2c
#endif

	__declspec(dllexport) virtual void ParseExtra(); // vtable+0x30

	inline void ProgressTickleState(TickleState p_tickleState)
	{
		m_previousTickleStates |= 1 << (MxU8) m_currentTickleState;
		m_currentTickleState = p_tickleState;
	}

public:
	// FUNCTION: LEGO1 0x1000bf70
	virtual MxResult AddToManager() { return SUCCESS; }; // vtable+0x34

	// FUNCTION: LEGO1 0x1000bf80
	virtual void Destroy() { Init(); }; // vtable+0x38

	__declspec(dllexport) virtual MxResult StartAction(MxStreamController*, MxDSAction*); // vtable+0x3c
	__declspec(dllexport) virtual void EndAction();                                       // vtable+0x40

	// FUNCTION: LEGO1 0x1000bf90
	virtual void SetTickleState(TickleState p_tickleState) { ProgressTickleState(p_tickleState); } // vtable+0x44

	// FUNCTION: LEGO1 0x1000bfb0
	virtual MxBool HasTickleStatePassed(TickleState p_tickleState)
	{
		return m_previousTickleStates & (1 << (MxU8) p_tickleState);
	}; // vtable+0x48

	// FUNCTION: LEGO1 0x1000bfc0
	virtual MxResult PutData() { return SUCCESS; }; // vtable+0x4c

	// FUNCTION: LEGO1 0x1000bfd0
	virtual MxBool IsHit(MxS32 p_x, MxS32 p_y) { return FALSE; }; // vtable+0x50

	__declspec(dllexport) virtual void Enable(MxBool p_enable); // vtable+0x54

	MxEntity* CreateEntity(const char* p_name);
	MxBool IsEnabled();

	inline MxS32 GetCurrentTickleState() const { return this->m_currentTickleState; }
	inline MxPoint32 GetLocation() const { return this->m_location; }
	inline MxS32 GetDisplayZ() const { return this->m_displayZ; }
	inline MxDSAction* GetAction() const { return this->m_action; }

	inline void SetCompositePresenter(MxCompositePresenter* p_compositePresenter)
	{
		m_compositePresenter = p_compositePresenter;
	}

protected:
	__declspec(dllexport) void Init();
	void SendToCompositePresenter(MxOmni*);

	TickleState m_currentTickleState;           // 0x8
	MxU32 m_previousTickleStates;               // 0x0c
	MxPoint32 m_location;                       // 0x10
	MxS32 m_displayZ;                           // 0x18
	MxDSAction* m_action;                       // 0x1c
	MxCriticalSection m_criticalSection;        // 0x20
	MxCompositePresenter* m_compositePresenter; // 0x3c
};

const char* PresenterNameDispatch(const MxDSAction&);

#endif // MXPRESENTER_H
