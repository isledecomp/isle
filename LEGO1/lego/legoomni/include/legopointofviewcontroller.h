#ifndef LEGOPOINTOFVIEWCONTROLLER_H
#define LEGOPOINTOFVIEWCONTROLLER_H
#include "decomp.h"
#include "mxcore.h"

class Lego3DView;
class LegoEntity;
class LegoNavController;

//////////////////////////////////////////////////////////////////////////////
//
// LegoMouseController

// VTABLE: LEGO1 0x100d8dd8
class LegoMouseController : public MxCore {
public:
	LegoMouseController();
	~LegoMouseController();

	virtual void LeftDown(int, int);  // vtable+0x14
	virtual void LeftDrag(int, int);  // vtable+0x18
	virtual void LeftUp(int, int);    // vtable+0x1c
	virtual void RightDown(int, int); // vtable+0x20
	virtual void RightDrag(int, int); // vtable+0x24
	virtual void RightUp(int, int);   // vtable+0x28

private:
	// note: in the leaked source code, this is a bool (which is typedefed to int)
	MxU32 m_isButtonDown; // 0x08
	undefined4 m_unk0xc;  // 0x0c
	MxDouble m_buttonX;   // 0x10
	MxDouble m_buttonY;   // 0x18
};

// VTABLE: LEGO1 0x100d8e08
class LegoPointOfViewController : public LegoMouseController {
public:
	LegoPointOfViewController();
	~LegoPointOfViewController();

	virtual MxResult Tickle(); // vtable+0x08

	MxResult Create(Lego3DView* p_lego3DView);

	void LeftDown(int x, int y);
	void LeftDrag(int x, int y);

	// FUNCTION: LEGO1 0x10011e40
	virtual void LeftUp(int x, int y)
	{
		LegoMouseController::LeftUp(x, y);
		AffectPointOfView();
	}
	override; // vtable+0x14

	// FUNCTION: LEGO1 0x10011e60
	virtual void RightDown(int x, int y)
	{
		LegoMouseController::RightDown(x, y);
		AffectPointOfView();
	}
	override; // vtable+0x20

	// FUNCTION: LEGO1 0x10011e80
	virtual void RightDrag(int x, int y)
	{
		LegoMouseController::RightDrag(x, y);
		AffectPointOfView();
	}
	override; // vtable+0x24

	// FUNCTION: LEGO1 0x10011ea0
	virtual void RightUp(int x, int y)
	{
		LegoMouseController::RightUp(x, y);
		AffectPointOfView();
	}
	override;                                     // vtable+0x28
	virtual void SetEntity(LegoEntity* p_entity); // vtable+0x2c
	LegoEntity* GetEntity() { return m_entity; }

protected:
	void AffectPointOfView();
	Lego3DView* m_lego3DView; // 0x20
	LegoEntity* m_entity;     // 0x24
	double m_entityOffsetUp;  // 0x28
	LegoNavController* m_nav; // 0x30
};
#endif /* LEGOPOINTOFVIEWCONTROLLER_H */
