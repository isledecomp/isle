#ifndef LEGOGAMESTATE_H
#define LEGOGAMESTATE_H

#include "decomp.h"
#include "legobackgroundcolor.h"
#include "legofullscreenmovie.h"
#include "legostream.h"
#include "mxtypes.h"

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
	__declspec(dllexport) LegoGameState();
	__declspec(dllexport) ~LegoGameState();
	__declspec(dllexport) MxResult Load(MxULong);
	__declspec(dllexport) MxResult Save(MxULong);
	__declspec(dllexport) void SerializePlayersInfo(MxS16);
	__declspec(dllexport) void SerializeScoreHistory(MxS16 p_flags);
	__declspec(dllexport) void SetSavePath(char*);

	LegoState* GetState(const char* p_stateName);
	LegoState* CreateState(const char* p_stateName);

	void GetFileSavePath(MxString* p_outPath, MxULong p_slotn);
	void FUN_1003a720(MxU32);
	void HandleAction(MxU32);

	inline MxU8 GetUnknownC() { return m_unk0xc; }
	inline MxU32 GetUnknown10() { return m_unk0x10; }
	inline MxS32 GetCurrentAct() { return m_currentAct; }
	inline undefined4 GetUnknown424() { return m_unk0x424; }
	inline void SetDirty(MxBool p_dirty) { m_isDirty = p_dirty; }
	inline void SetUnknown424(undefined4 p_unk0x424) { m_unk0x424 = p_unk0x424; }

	void SetSomeEnumState(undefined4 p_state);
	void FUN_1003ceb0();

	struct ScoreStruct {
		void WriteScoreHistory();
		void FUN_1003ccf0(LegoFileStream&);

		MxU16 m_unk0x00;
		undefined m_unk0x02[0x2c][20];
	};

private:
	void RegisterState(LegoState* p_state);
	MxResult WriteEndOfVariables(LegoStream* p_stream);
	void SetROIHandlerFunction();

	char* m_savePath;                           // 0x0
	MxS16 m_stateCount;                         // 0x4
	LegoState** m_stateArray;                   // 0x8
	MxU8 m_unk0xc;                              // 0xc
	MxU32 m_unk0x10;                            // 0x10
	MxS32 m_currentAct;                         // 0x14
	LegoBackgroundColor* m_backgroundColor;     // 0x18
	LegoBackgroundColor* m_tempBackgroundColor; // 0x1c
	LegoFullScreenMovie* m_fullScreenMovie;     // 0x20
	MxU16 m_unk0x24;                            // 0x24
	undefined m_unk0x28[128];                   // 0x28
	ScoreStruct m_unk0xa6;                      // 0xa6
	undefined m_unk0x41a[8];                    // 0x41a - might be part of the structure at 0xa6
	MxBool m_isDirty;                           // 0x420
	undefined4 m_unk0x424;                      // 0x424
	undefined4 m_unk0x428;                      // 0x428
	undefined4 m_unk0x42c;                      // 0x42c
};

MxBool ROIHandlerFunction(char* p_input, char* p_output, MxU32 p_copyLen);

#endif // LEGOGAMESTATE_H
