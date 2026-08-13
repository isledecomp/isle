enum LegoSoundFlag0 {
	c_legoSoundFlag0 = 1 << 0
};
class LegoSoundCounter0 {
public:
	int GetValue() { return m_value; }

private:
	int m_value;
};
class LegoSoundCounter1 {
public:
	int GetValue() { return m_value; }

private:
	int m_value;
};
class LegoSoundCounter2 {
public:
	int GetValue() { return m_value; }

private:
	int m_value;
};
class LegoSoundRange0 {
public:
	int GetFirst() { return m_first; }
	int GetLast() { return m_last; }

private:
	int m_first;
	int m_last;
};
class LegoSoundRange1 {
public:
	int GetFirst() { return m_first; }
	int GetLast() { return m_last; }

private:
	int m_first;
	int m_last;
};
class LegoSoundRange2 {
public:
	int GetFirst() { return m_first; }
	int GetLast() { return m_last; }

private:
	int m_first;
	int m_last;
};
class LegoSoundRange3 {
public:
	int GetFirst() { return m_first; }
	int GetLast() { return m_last; }

private:
	int m_first;
	int m_last;
};
class LegoSoundRange4 {
public:
	int GetFirst() { return m_first; }
	int GetLast() { return m_last; }

private:
	int m_first;
	int m_last;
};

#include "legocachesoundmanager.h"

// This translation unit exists to supply the out-of-line `insert` of the
// Set100d6b4c red-black tree, together with the four tree members it calls --
// taking insert's address cannot force it alone. Retail emits the whole group
// from a separate object, and it only reproduces byte-exactly when compiled in
// its own translation unit. The declarations above the include are a stand-in
// for the 1997 source text that occupied this file; replace them if it is ever
// recovered.

// clang-format off
// MSVC 4.20 parses `>>` as a shift, so the closing angle brackets must stay split.
typedef _Tree<
	LegoCacheSoundEntry,
	LegoCacheSoundEntry,
	Set100d6b4c::_Kfn,
	Set100d6b4cComparator,
	allocator<LegoCacheSoundEntry>
> CacheSoundEntryTree;
// clang-format on

struct CacheSoundEntryInsertProbe : public CacheSoundEntryTree {
	typedef _Pairib (CacheSoundEntryTree::*Fn)(const value_type&);
	static Fn Get();
};

CacheSoundEntryInsertProbe::Fn CacheSoundEntryInsertProbe::Get()
{
	return &CacheSoundEntryTree::insert;
}
