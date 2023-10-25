#include "mxatomidcounter.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxAtomIdCounter, 0x14);
DECOMP_SIZE_ASSERT(MxAtomIdCounterSet, 0x10);

// OFFSET: LEGO1 0x100ad7f0
void MxAtomIdCounter::Inc()
{
	m_value++;
}

// OFFSET: LEGO1 0x100ad800
void MxAtomIdCounter::Dec()
{
	if (m_value)
		m_value--;
}
