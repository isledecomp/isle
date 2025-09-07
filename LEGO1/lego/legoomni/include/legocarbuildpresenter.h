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

	enum ShelfState {
		e_undefined = -1,
		e_selected = 0,
		e_stopped = 1,
		e_moving = 2
	};

	// SIZE 0x0c
	struct CarBuildPart {
		// FUNCTION: LEGO1 0x100795c0
		// FUNCTION: BETA10 0x10073850
		CarBuildPart()
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

	void MakePartPlaced(MxS16 p_index);
	void SwapNodesByName(LegoChar* p_param1, LegoChar* p_param2);
	void InitBuildPlatform();
	void HideBuildPartByName(LegoChar* p_param);
	void ShowBuildPartByName(LegoChar* p_param);
	LegoAnimNodeData* FindNodeDataByName(LegoTreeNode* p_treeNode, const LegoChar* p_name);
	LegoTreeNode* FindNodeByName(LegoTreeNode* p_treeNode, const LegoChar* p_name);
	void AddPartToBuildByName(const LegoChar* p_name);
	void RotateAroundYAxis(MxFloat p_angle);
	MxBool IsNextPartToPlace(const LegoChar* p_name);
	MxBool PartIsPlaced(const LegoChar* p_name);
	void MoveShelfForward();
	MxBool StringEqualsPlatform(const LegoChar* p_string);
	MxBool StringEqualsShelf(const LegoChar* p_string);
	MxBool StringEndsOnY(const LegoChar* p_string);
	MxBool StringDoesNotEndOnZero(const LegoChar* p_string);
	const LegoChar* GetWiredNameByPartName(const LegoChar* p_name);
	void SetPartObjectIdByName(const LegoChar* p_name, MxS16 p_objectId);

	// FUNCTION: BETA10 0x10070180
	void SetShelfState(MxU16 p_shelfState) { m_shelfState = p_shelfState; }

	// FUNCTION: BETA10 0x100703b0
	Matrix4& GetBuildViewMatrix() { return m_buildViewMatrix; }

	MxBool StringEndsOnW(LegoChar* p_param);
	MxBool StringEndsOnYOrN(const LegoChar* p_string);

	const BoundingSphere& GetTargetBoundingSphere();

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
	void UpdateFlashingPartVisibility();

	MxU16 m_shelfState; // 0xbc

	// variable name verified by BETA10 0x1007184f
	MxS16 m_numberOfParts; // 0xbe

	// name derived from LegoVehicleBuildState, field 0x4f
	MxS16 m_placedPartCount; // 0xc0

	LegoAnimNodeData* m_platformAnimNodeData; // 0xc4
	LegoAnim m_platformAnim;                  // 0xc8
	MxMatrix m_buildViewMatrix;               // 0xe0

	// variable name verified by BETA10 0x100719f0
	CarBuildPart* m_parts; // 0x128

	MxFloat m_shelfFrameBuffer;      // 0x12c
	MxFloat m_shelfFrame;            // 0x130
	MxFloat m_shelfFrameMax;         // 0x134
	MxFloat m_shelfFrameInterval;    // 0x138
	MxULong m_flashingPartTimeState; // 0x13c
	LegoEntity* m_carBuildEntity;    // 0x140
	MxS32 m_unk0x144;                // 0x144
	MxS32 m_unk0x148;                // 0x148

	// name verified by BETA10 0x10070d63
	LegoChar* m_mainSourceId; // 0x14c
};

#endif // LEGOCARBUILDPRESENTER_H
