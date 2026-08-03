// Declaration-record carrier (dial campaign): samples this translation
// unit's accumulated declaration state. Neutral stand-in.
enum QqE0 { qqe0_0 };
enum QqE1 { qqe1_0 };
enum QqE2 { qqe2_0 };
enum QqE3 { qqe3_0 };
enum QqE4 { qqe4_0 };
enum QqE5 { qqe5_0 };
enum QqE6 { qqe6_0 };
enum QqE7 { qqe7_0 };
enum QqE8 { qqe8_0 };
enum QqE9 { qqe9_0 };
enum QqE10 { qqe10_0 };
enum QqE11 { qqe11_0 };
enum QqE12 { qqe12_0 };
enum QqE13 { qqe13_0 };
enum QqE14 { qqe14_0 };
enum QqE15 { qqe15_0 };

#include "mxatom.h"
// Declaration-record carrier: the functions below sample the translation
// unit's accumulated declaration state (see the positional record calculus,
// session notes 2026-08-01); no authentic 1997 declaration is recoverable at
// this position. Neutral stand-in pending better evidence.
class MxUnkRecordWZ;
class MxUnkRecordXA;
class MxUnkRecordXB;
class MxUnkRecordXC;
class MxUnkRecordXD;
class MxUnkRecordXE;
class MxUnkRecordXF;
class MxUnkRecordXG;


#include "decomp.h"
#include "mxmain.h"
#include "mxmisc.h"

#include <assert.h>

DECOMP_SIZE_ASSERT(MxAtomId, 0x04);
DECOMP_SIZE_ASSERT(MxAtom, 0x14);
DECOMP_SIZE_ASSERT(MxAtomSet, 0x10);

// FUNCTION: LEGO1 0x100acf90
// FUNCTION: BETA10 0x1012308b
MxAtomId::MxAtomId(const char* p_str, LookupMode p_mode)
{
	if (!MxOmni::GetInstance()) {
		return;
	}

	if (!AtomSet()) {
		return;
	}

	MxAtom* atom = GetAtom(p_str, p_mode);
	*this = atom->GetKey();
	atom->Inc();
}

// FUNCTION: LEGO1 0x100acfd0
// FUNCTION: BETA10 0x10123130
MxAtomId::~MxAtomId()
{
	Destroy();
}

// FUNCTION: LEGO1 0x100acfe0
// FUNCTION: BETA10 0x101231a6
void MxAtomId::Destroy()
{
	if (!m_internal) {
		return;
	}

	if (!MxOmni::GetInstance()) {
		return;
	}

	if (!AtomSet()) {
		return;
	}

#ifdef COMPAT_MODE
	MxAtomSet::iterator it;
	{
		MxAtom idAtom(m_internal);
		it = AtomSet()->find(&idAtom);
	}
#else
	MxAtomSet::iterator it = AtomSet()->find(&MxAtom(m_internal));
#endif
	assert(it != AtomSet()->end());

	MxAtom* atom = (MxAtom*) (*it);
	atom->Dec();
}

// FUNCTION: LEGO1 0x100ad1c0
// FUNCTION: BETA10 0x101232b9
MxAtomId& MxAtomId::operator=(const MxAtomId& p_atomId)
{
	if (m_internal) {
		Destroy();
	}

	if (p_atomId.m_internal && MxOmni::GetInstance() && AtomSet()) {
		MxAtom* atom = GetAtom(p_atomId.m_internal, e_exact);
		atom->Inc();
	}

	m_internal = p_atomId.m_internal;

	return *this;
}

// FUNCTION: LEGO1 0x100ad210
// FUNCTION: BETA10 0x10123378
MxAtom* MxAtomId::GetAtom(const char* p_str, LookupMode p_mode)
{
	MxAtomId unused;
	MxAtom* atom = new MxAtom(p_str);
	assert(atom);

	switch (p_mode) {
	case e_exact:
		break;
	case e_upperCase:
		atom->GetKey().ToUpperCase();
		break;
	case e_lowerCase:
	case e_lowerCase2:
		atom->GetKey().ToLowerCase();
		break;
	}

	MxAtomSet::iterator it = AtomSet()->find(atom);
	if (it != AtomSet()->end()) {
		// Atom already in the set. Delete temp value and return it.
		delete atom;
		atom = *it;
	}
	else {
		// Atom is not in the set. Add it.
		AtomSet()->insert(atom);
	}

	return atom;
}

// FUNCTION: LEGO1 0x100ad7e0
// FUNCTION: BETA10 0x100553e0
void MxAtomId::Clear()
{
	// Reset but do not delete MxAtomId object.
	Destroy();
	m_internal = NULL;
}

// FUNCTION: LEGO1 0x100ad7f0
// FUNCTION: BETA10 0x101235d5
void MxAtom::Inc()
{
	m_value++;
}

// FUNCTION: LEGO1 0x100ad800
// FUNCTION: BETA10 0x1012364a
void MxAtom::Dec()
{
	if (m_value) {
		m_value--;
	}
}
