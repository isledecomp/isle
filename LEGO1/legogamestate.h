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

// SIZE 0x430
class LegoGameState {
public:
	__declspec(dllexport) LegoGameState();
	__declspec(dllexport) ~LegoGameState();
	__declspec(dllexport) MxResult Load(MxULong);
	__declspec(dllexport) MxResult Save(MxULong);
	__declspec(dllexport) void SerializePlayersInfo(MxS16);
	__declspec(dllexport) void SerializeScoreHistory(MxS16);
	__declspec(dllexport) void SetSavePath(char*);

	LegoState* GetState(COMPAT_CONST char* p_stateName);
	LegoState* CreateState(COMPAT_CONST char* p_stateName);

	void GetFileSavePath(MxString* p_outPath, MxULong p_slotn);
	void FUN_1003a720(MxU32);
	void HandleAction(MxU32);

	inline MxU8 GetUnknownC() { return m_unk0xc; }
	inline MxU32 GetUnknown10() { return m_unk0x10; }
	inline void SetUnknown424(undefined4 p_unk0x424) { m_unk0x424 = p_unk0x424; }

	void SetSomeEnumState(undefined4 p_state);

private:
	void RegisterState(LegoState* p_state);
	MxResult WriteEndOfVariables(LegoStream* p_stream);
	void SetROIHandlerFunction();

private:
	char* m_savePath;                           // 0x0
	MxS16 m_stateCount;                         // 0x4
	LegoState** m_stateArray;                   // 0x8
	MxU8 m_unk0xc;                              // 0xc
	MxU32 m_unk0x10;                            // 0x10
	undefined4 m_unk0x14;                       // 0x14
	LegoBackgroundColor* m_backgroundColor;     // 0x18
	LegoBackgroundColor* m_tempBackgroundColor; // 0x1c
	LegoFullScreenMovie* m_fullScreenMovie;     // 0x20
	MxU16 m_unk0x24;                            // 0x24
	undefined m_unk0x28[1020];                  // 0x28
	undefined4 m_unk0x424;                      // 0x424
	undefined4 m_unk0x428;                      // 0x428
	undefined4 m_unk0x42c;                      // 0x42c
};

MxBool ROIHandlerFunction(char* p_input, char* p_output, MxU32 p_copyLen);

#endif // LEGOGAMESTATE_H
