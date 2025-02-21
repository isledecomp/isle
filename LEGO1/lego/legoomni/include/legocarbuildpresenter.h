#ifndef LEGOCARBUILDPRESENTER_H
#define LEGOCARBUILDPRESENTER_H

#include "anim/legoanim.h"
#include "legoanimpresenter.h"

// VTABLE: LEGO1 0x100d99e0
// VTABLE: BETA10 0x101bb988
// SIZE 0x150
class LegoCarBuildAnimPresenter : public LegoAnimPresenter {
public:
	enum {
		c_bit1 = 0x01
	};

	// SIZE 0x0c
	struct UnknownListEntry {
		// FUNCTION: LEGO1 0x100795c0
		// FUNCTION: BETA10 0x10073850
		UnknownListEntry()
		{
			m_name = NULL;
			m_wiredName = NULL;
			m_objectId = 0;
		}

		// variable name verified by BETA10 0x10071b56
		LegoChar* m_name; // 0x00

		// variable name verified by BETA10 0x100719f0
		LegoChar* m_wiredName; // 0x04

		// variable name guessed based on the setter at LEGO1 0x0x10079dc0 and its use in LEGO1 0x10024890
		MxS16 m_objectId; // 0x08
	};

	LegoCarBuildAnimPresenter();
	~LegoCarBuildAnimPresenter() override; // vtable+0x00

	// FUNCTION: BETA10 0x10073290
	static const char* HandlerClassName()
	{
		// STRING: LEGO1 0x100f05ec
		return "LegoCarBuildAnimPresenter";
	}

	// FUNCTION: LEGO1 0x10078500
	void RepeatingTickle() override {} // vtable+0x24

	// FUNCTION: LEGO1 0x10078510
	// FUNCTION: BETA10 0x10073260
	const char* ClassName() const override // vtable+0x0c
	{
		return HandlerClassName();
	}

	// FUNCTION: LEGO1 0x10078520
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoCarBuildAnimPresenter::ClassName()) || LegoAnimPresenter::IsA(p_name);
	}

	void ReadyTickle() override;     // vtable+0x18
	void StreamingTickle() override; // vtable+0x20
	void EndAction() override;       // vtable+0x40
	void PutFrame() override;        // vtable+0x6c

	virtual MxResult Serialize(LegoStorage* p_storage);

	void FUN_10079050(MxS16 p_index);
	void SwapNodesByName(LegoChar* p_param1, LegoChar* p_param2);
	void FUN_10079160();
	void FUN_100795d0(LegoChar* p_param);
	void FUN_10079680(LegoChar* p_param);
	LegoAnimNodeData* FindNodeDataByName(LegoTreeNode* p_treeNode, const LegoChar* p_name);
	LegoTreeNode* FindNodeByName(LegoTreeNode* p_treeNode, const LegoChar* p_name);
	void FUN_10079790(const LegoChar* p_name);
	void RotateAroundYAxis(MxFloat p_angle);
	MxBool FUN_10079c30(const LegoChar* p_name);
	MxBool PartIsPlaced(const LegoChar* p_name);
	void FUN_10079a90();
	MxBool StringEqualsPlatform(const LegoChar* p_string);
	MxBool StringEqualsShelf(const LegoChar* p_string);
	MxBool StringEndsOnY(const LegoChar* p_string);
	MxBool StringDoesNotEndOnZero(const LegoChar* p_string);
	const LegoChar* GetWiredNameByPartName(const LegoChar* p_name);
	void SetPartObjectIdByName(const LegoChar* p_name, MxS16 p_objectId);

	// FUNCTION: BETA10 0x10070180
	void SetUnknown0xbc(undefined2 p_unk0xbc) { m_unk0xbc = p_unk0xbc; }

	// FUNCTION: BETA10 0x100703b0
	Matrix4& GetUnknown0xe0() { return m_unk0xe0; }

	MxBool StringEndsOnW(LegoChar* p_param);
	MxBool StringEndsOnYOrN(const LegoChar* p_string);

	const BoundingSphere& FUN_10079e20();

	// FUNCTION: BETA10 0x100703e0
	const LegoChar* GetWiredNameOfLastPlacedPart() { return m_parts[m_placedPartCount].m_wiredName; }

	MxS16 GetNumberOfParts() { return m_numberOfParts; }
	MxS16 GetPlacedPartCount() { return m_placedPartCount; }

	// FUNCTION: BETA10 0x10070270
	MxBool AllPartsPlaced()
	{
		// this function differs in BETA10
		return m_placedPartCount == m_numberOfParts;
	}

	// SYNTHETIC: LEGO1 0x10078660
	// LegoCarBuildAnimPresenter::`scalar deleting destructor'

private:
	void Beta10Inline0x100733d0();

	MxU16 m_unk0xbc; // 0xbc

	// variable name verified by BETA10 0x1007184f
	MxS16 m_numberOfParts; // 0xbe

	// name derived from LegoVehicleBuildState, field 0x4f
	MxS16 m_placedPartCount; // 0xc0

	LegoAnimNodeData* m_unk0xc4; // 0xc4
	LegoAnim m_unk0xc8;          // 0xc8
	MxMatrix m_unk0xe0;          // 0xe0

	// variable name verified by BETA10 0x100719f0
	UnknownListEntry* m_parts; // 0x128

	MxFloat m_unk0x12c;     // 0x12c
	MxFloat m_unk0x130;     // 0x130
	MxFloat m_unk0x134;     // 0x134
	MxFloat m_unk0x138;     // 0x138
	MxULong m_unk0x13c;     // 0x13c
	LegoEntity* m_unk0x140; // 0x140
	MxS32 m_unk0x144;       // 0x144
	MxS32 m_unk0x148;       // 0x148

	// name verified by BETA10 0x10070d63
	LegoChar* m_mainSourceId; // 0x14c
};

#endif // LEGOCARBUILDPRESENTER_H
