#ifndef LEGOGAMESTATE_H
#define LEGOGAMESTATE_H

#include "decomp.h"
#include "legobackgroundcolor.h"
#include "legofullscreenmovie.h"
#include "mxtypes.h"

class LegoState;
class LegoStream;
class MxVariable;
class MxString;

struct ColorStringStruct {
	const char* m_targetName;
	const char* m_colorName;
};

// SIZE 0x430 (at least)
class LegoGameState {
public:
	__declspec(dllexport) LegoGameState();
	__declspec(dllexport) ~LegoGameState();
	__declspec(dllexport) MxResult Load(MxULong);
	__declspec(dllexport) MxResult Save(MxULong p);
	__declspec(dllexport) void SerializePlayersInfo(MxS16 p);
	__declspec(dllexport) void SerializeScoreHistory(MxS16 p);
	__declspec(dllexport) void SetSavePath(char* p);

	LegoState* GetState(COMPAT_CONST char* p_stateName);
	LegoState* CreateState(COMPAT_CONST char* p_stateName);

	void GetFileSavePath(MxString* p_outPath, MxULong p_slotn);
	void FUN_1003a720(MxU32 p_unk);
	void HandleAction(MxU32 p_unk);

	inline MxU32 GetUnknown10() { return m_unk10; }
	inline void SetUnknown424(undefined4 p_unk424) { m_unk424 = p_unk424; }

private:
	void RegisterState(LegoState* p_state);
	MxResult WriteEndOfVariables(LegoStream* p_stream);
	void SetROIHandlerFunction();

private:
	char* m_savePath; // 0x0
	MxS16 m_stateCount;
	LegoState** m_stateArray;
	MxU8 m_unkC;
	MxU32 m_unk10;
	undefined4 m_unk0x14;
	LegoBackgroundColor* m_backgroundColor;     // 0x18
	LegoBackgroundColor* m_tempBackgroundColor; // 0x1c
	LegoFullScreenMovie* m_fullScreenMovie;     // 0x20
	MxU16 m_unk24;                              // 0x24
	undefined m_unk28[1020];
	undefined4 m_unk424;
	undefined4 m_unk428;
	undefined4 m_unk42c;
};

MxBool ROIHandlerFunction(char* p_0, char* p_output, MxU32 p_copyLen);

#endif // LEGOGAMESTATE_H
