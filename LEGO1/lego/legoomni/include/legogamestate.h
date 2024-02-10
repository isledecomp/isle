#ifndef LEGOGAMESTATE_H
#define LEGOGAMESTATE_H

#include "decomp.h"
#include "lego/sources/misc/legostorage.h"
#include "legobackgroundcolor.h"
#include "legofullscreenmovie.h"
#include "mxtypes.h"
#include "mxvariabletable.h"

class LegoState;
class MxVariable;
class MxString;

struct ColorStringStruct {
	const char* m_targetName;
	const char* m_colorName;
};

// SIZE 0x430
class LegoGameState {
public:
	enum Act {
		e_actNotFound = -1,
		e_act1 = 0,
		e_act2 = 1,
		e_act3 = 2
	};

	LegoGameState();
	~LegoGameState();

	MxResult Load(MxULong);
	MxResult Save(MxULong);
	void SerializePlayersInfo(MxS16);
	void SerializeScoreHistory(MxS16 p_flags);
	void SetSavePath(char*);

	LegoState* GetState(const char* p_stateName);
	LegoState* CreateState(const char* p_stateName);

	void GetFileSavePath(MxString* p_outPath, MxULong p_slotn);
	void StopArea(MxU32 p_area = 0);
	void SwitchArea(MxU32 p_area);

	inline MxU8 GetUnknownC() { return m_unk0x0c; }
	inline Act GetCurrentAct() { return m_currentAct; }
	inline Act GetLoadedAct() { return m_loadedAct; }
	inline MxU32 GetCurrentArea() { return m_currentArea; }
	inline MxU32 GetPreviousArea() { return m_previousArea; }
	inline MxU32 GetUnknown0x42c() { return m_unk0x42c; }

	inline void SetDirty(MxBool p_dirty) { m_isDirty = p_dirty; }
	inline void SetCurrentArea(MxU32 p_currentArea) { m_currentArea = p_currentArea; }
	inline void SetPreviousArea(MxU32 p_previousArea) { m_previousArea = p_previousArea; }
	inline void SetUnknown0x0c(MxU8 p_unk0x0c) { m_unk0x0c = p_unk0x0c; }
	inline void SetUnknown0x42c(undefined4 p_unk0x42c) { m_unk0x42c = p_unk0x42c; }

	void SetCurrentAct(Act p_currentAct);
	void FindLoadedAct();
	void FUN_10039780(MxU8);
	void FUN_10039940();

	struct ScoreStruct {
		void WriteScoreHistory();
		void FUN_1003ccf0(LegoFile&);

		MxU16 m_unk0x00;
		undefined m_unk0x02[0x2c][20];
	};

private:
	void RegisterState(LegoState* p_state);
	MxResult WriteVariable(LegoStorage* p_stream, MxVariableTable* p_from, const char* p_variableName);
	MxResult WriteEndOfVariables(LegoStorage* p_stream);
	MxS32 ReadVariable(LegoStorage* p_stream, MxVariableTable* p_to);
	void SetROIHandlerFunction();

	char* m_savePath;                           // 0x00
	MxS16 m_stateCount;                         // 0x04
	LegoState** m_stateArray;                   // 0x08
	MxU8 m_unk0x0c;                             // 0x0c
	Act m_currentAct;                           // 0x10
	Act m_loadedAct;                            // 0x14
	LegoBackgroundColor* m_backgroundColor;     // 0x18
	LegoBackgroundColor* m_tempBackgroundColor; // 0x1c
	LegoFullScreenMovie* m_fullScreenMovie;     // 0x20
	MxU16 m_unk0x24;                            // 0x24
	undefined m_unk0x28[128];                   // 0x28
	ScoreStruct m_unk0xa6;                      // 0xa6
	undefined m_unk0x41a[8];                    // 0x41a - might be part of the structure at 0xa6
	MxBool m_isDirty;                           // 0x420
	MxU32 m_currentArea;                        // 0x424
	MxU32 m_previousArea;                       // 0x428
	undefined4 m_unk0x42c;                      // 0x42c
};

MxBool ROIHandlerFunction(char* p_input, char* p_output, MxU32 p_copyLen);

#endif // LEGOGAMESTATE_H
