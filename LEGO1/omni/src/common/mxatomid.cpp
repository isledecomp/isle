#include "mxatomid.h"

#include "mxomni.h"

// FUNCTION: LEGO1 0x100acf90
MxAtomId::MxAtomId(const char* p_str, LookupMode p_mode)
{
	if (!MxOmni::GetInstance()) {
		return;
	}

	if (!AtomIdCounterSet()) {
		return;
	}

	MxAtomIdCounter* counter = GetCounter(p_str, p_mode);
	m_internal = counter->GetKey()->GetData();
	counter->Inc();
}

// FUNCTION: LEGO1 0x100acfd0
MxAtomId::~MxAtomId()
{
	Destroy();
}

// FUNCTION: LEGO1 0x100acfe0
void MxAtomId::Destroy()
{
	if (!m_internal) {
		return;
	}

	if (!MxOmni::GetInstance()) {
		return;
	}

	if (!AtomIdCounterSet()) {
		return;
	}

#ifdef COMPAT_MODE
	MxAtomIdCounterSet::iterator it;
	{
		MxAtomIdCounter id_counter(m_internal);
		it = AtomIdCounterSet()->find(&id_counter);
	}
#else
	MxAtomIdCounterSet::iterator it = AtomIdCounterSet()->find(&MxAtomIdCounter(m_internal));
#endif

	MxAtomIdCounter* counter = (MxAtomIdCounter*) (*it);
	counter->Dec();
}

// FUNCTION: LEGO1 0x100ad1c0
MxAtomId& MxAtomId::operator=(const MxAtomId& p_atomId)
{
	if (m_internal) {
		Destroy();
	}

	if (p_atomId.m_internal && MxOmni::GetInstance() && AtomIdCounterSet()) {
		MxAtomIdCounter* counter = GetCounter(p_atomId.m_internal, e_exact);
		counter->Inc();
	}

	m_internal = p_atomId.m_internal;

	return *this;
}

// FUNCTION: LEGO1 0x100ad210
MxAtomIdCounter* MxAtomId::GetCounter(const char* p_str, LookupMode p_mode)
{
	MxAtomId unused;
	MxAtomIdCounter* counter = new MxAtomIdCounter(p_str);

	switch (p_mode) {
	case e_lowerCase:
	case e_lowerCase2:
		counter->GetKey()->ToLowerCase();
		break;
	case e_upperCase:
		counter->GetKey()->ToUpperCase();
		break;
	}

	MxAtomIdCounterSet::iterator it = AtomIdCounterSet()->find(counter);
	if (it != AtomIdCounterSet()->end()) {
		// Counter already in the set. Delete temp value and return it.
		delete counter;
		counter = *it;
	}
	else {
		// Counter is not in the set. Add it.
		AtomIdCounterSet()->insert(counter);
	}

	return counter;
}

// FUNCTION: LEGO1 0x100ad7e0
void MxAtomId::Clear()
{
	// Reset but do not delete MxAtomId object.
	Destroy();
	m_internal = NULL;
}
