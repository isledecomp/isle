#ifndef MXPRESENTER_H
#define MXPRESENTER_H

#include "decomp.h"
#include "mxcore.h"
#include "mxcriticalsection.h"
#include "mxgeometry.h"

class MxCompositePresenter;
class MxDSAction;
class MxOmni;
class MxStreamController;
class MxEntity;

// VTABLE: LEGO1 0x100d4d38
// SIZE 0x40
class MxPresenter : public MxCore {
public:
	enum TickleState {
		e_idle = 0,
		e_ready,
		e_starting,
		e_streaming,
		e_repeating,
		e_freezing,
		e_done,
	};

	MxPresenter() { Init(); }

	MxResult Tickle() override; // vtable+0x08

	// FUNCTION: LEGO1 0x1000be30
	virtual void VTable0x14() {} // vtable+0x14

	// FUNCTION: LEGO1 0x1000be40
	virtual void ReadyTickle()
	{
		ParseExtra();
		ProgressTickleState(e_starting);
	} // vtable+0x18

	// FUNCTION: LEGO1 0x1000be60
	virtual void StartingTickle() { ProgressTickleState(e_streaming); } // vtable+0x1c

	// FUNCTION: LEGO1 0x1000be80
	virtual void StreamingTickle() { ProgressTickleState(e_repeating); } // vtable+0x20

	// FUNCTION: LEGO1 0x1000bea0
	virtual void RepeatingTickle() { ProgressTickleState(e_freezing); } // vtable+0x24

	// FUNCTION: LEGO1 0x1000bec0
	virtual void FreezingTickle() { ProgressTickleState(e_done); } // vtable+0x28

protected:
	// FUNCTION: LEGO1 0x1000bee0
	virtual void DoneTickle() { ProgressTickleState(e_idle); } // vtable+0x2c

	virtual void ParseExtra(); // vtable+0x30

	void ProgressTickleState(TickleState p_tickleState)
	{
		m_previousTickleStates |= 1 << (MxU8) m_currentTickleState;
		m_currentTickleState = p_tickleState;
	}

public:
	// FUNCTION: LEGO1 0x1000bf00
	~MxPresenter() override {} // vtable+0x00

	// FUNCTION: LEGO1 0x1000bf70
	virtual MxResult AddToManager() { return SUCCESS; } // vtable+0x34

	// FUNCTION: LEGO1 0x1000bf80
	virtual void Destroy() { Init(); } // vtable+0x38

	virtual MxResult StartAction(MxStreamController*, MxDSAction*); // vtable+0x3c
	virtual void EndAction();                                       // vtable+0x40

	// FUNCTION: LEGO1 0x1000bf90
	// FUNCTION: BETA10 0x10054a50
	virtual void SetTickleState(TickleState p_tickleState) { ProgressTickleState(p_tickleState); } // vtable+0x44

	// FUNCTION: LEGO1 0x1000bfb0
	virtual MxBool HasTickleStatePassed(TickleState p_tickleState)
	{
		return m_previousTickleStates & (1 << (MxU8) p_tickleState);
	} // vtable+0x48

	// FUNCTION: LEGO1 0x1000bfc0
	virtual MxResult PutData() { return SUCCESS; } // vtable+0x4c

	// FUNCTION: LEGO1 0x1000bfd0
	virtual MxBool IsHit(MxS32 p_x, MxS32 p_y) { return FALSE; } // vtable+0x50

	virtual void Enable(MxBool p_enable); // vtable+0x54

	// FUNCTION: BETA10 0x1004d9e0
	static const char* HandlerClassName()
	{
		// STRING: LEGO1 0x100f0740
		return "MxPresenter";
	}

	// FUNCTION: LEGO1 0x1000bfe0
	// FUNCTION: BETA10 0x1004d9b0
	const char* ClassName() const override // vtable+0x0c
	{
		return HandlerClassName();
	}

	// FUNCTION: LEGO1 0x1000bff0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxPresenter::ClassName()) || MxCore::IsA(p_name);
	}

	MxEntity* CreateEntity(const char* p_defaultName);
	void SendToCompositePresenter(MxOmni* p_omni);
	MxBool IsEnabled();

	MxS32 GetCurrentTickleState() const { return this->m_currentTickleState; }
	MxPoint32 GetLocation() const { return this->m_location; }
	MxS32 GetX() const { return this->m_location.GetX(); }
	MxS32 GetY() const { return this->m_location.GetY(); }

	// FUNCTION: BETA10 0x10031b70
	MxS32 GetDisplayZ() const { return this->m_displayZ; }

	// FUNCTION: BETA10 0x10028430
	MxDSAction* GetAction() const { return this->m_action; }

	void SetAction(MxDSAction* p_action) { m_action = p_action; }

	void SetCompositePresenter(MxCompositePresenter* p_compositePresenter)
	{
		m_compositePresenter = p_compositePresenter;
	}

	// FUNCTION: BETA10 0x10031b40
	void SetDisplayZ(MxS32 p_displayZ) { m_displayZ = p_displayZ; }

	// SYNTHETIC: LEGO1 0x1000c070
	// MxPresenter::`scalar deleting destructor'

protected:
	void Init();

	TickleState m_currentTickleState;           // 0x08
	MxU32 m_previousTickleStates;               // 0x0c
	MxPoint32 m_location;                       // 0x10
	MxS32 m_displayZ;                           // 0x18
	MxDSAction* m_action;                       // 0x1c
	MxCriticalSection m_criticalSection;        // 0x20
	MxCompositePresenter* m_compositePresenter; // 0x3c
};

const char* PresenterNameDispatch(const MxDSAction&);

#endif // MXPRESENTER_H
