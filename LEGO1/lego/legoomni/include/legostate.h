#ifndef LEGOSTATE_H
#define LEGOSTATE_H

#include "decomp.h"
#include "lego/sources/misc/legostorage.h"
#include "mxcore.h"
#include "mxstring.h"

// VTABLE: LEGO1 0x100d46c0
// SIZE 0x08
class LegoState : public MxCore {
public:
	// FUNCTION: LEGO1 0x10005f40
	~LegoState() override {}

	// FUNCTION: LEGO1 0x100060d0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f01b8
		return "LegoState";
	}

	// FUNCTION: LEGO1 0x100060e0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoState::ClassName()) || MxCore::IsA(p_name);
	}

	// FUNCTION: LEGO1 0x10005f90
	virtual MxBool VTable0x14() { return TRUE; } // vtable+0x14

	// FUNCTION: LEGO1 0x10005fa0
	virtual MxBool SetFlag() { return FALSE; } // vtable+0x18

	// FUNCTION: LEGO1 0x10005fb0
	virtual MxResult VTable0x1c(LegoFile* p_legoFile)
	{
		if (p_legoFile->IsWriteMode()) {
			p_legoFile->FUN_10006030(this->ClassName());
		}
		return SUCCESS;
	} // vtable+0x1c

	// SYNTHETIC: LEGO1 0x10006160
	// LegoState::`scalar deleting destructor'

	// SIZE 0x0c
	class Playlist {
	public:
		enum Mode {
			e_loop,
			e_once,
			e_random,
			e_loopSkipFirst
		};

		// FUNCTION: LEGO1 0x10017c00
		Playlist()
		{
			m_objectIds = NULL;
			m_length = 0;
			m_mode = e_loop;
			m_nextIndex = 0;
		}

		Playlist(MxU32* p_objectIds, MxS16 p_length)
		{
			m_objectIds = p_objectIds;
			m_length = p_length;
			m_mode = e_loop;
			m_nextIndex = 0;
		}

		// FUNCTION: LEGO1 0x10071800
		Playlist& operator=(const Playlist& p_shuffle)
		{
			m_objectIds = p_shuffle.m_objectIds;
			m_length = p_shuffle.m_length;
			m_nextIndex = p_shuffle.m_nextIndex;
			m_mode = p_shuffle.m_mode;
			return *this;
		}

		MxU32 Next();
		MxBool Contains(MxU32 p_objectId);

		inline void SetUnknown0x08(MxS16 p_unk0x08) { m_nextIndex = p_unk0x08; }

	private:
		MxU32* m_objectIds; // 0x00
		MxS16 m_length;     // 0x04
		MxS16 m_mode;       // 0x06
		MxS16 m_nextIndex;  // 0x08
	};
};

#endif // LEGOSTATE_H
