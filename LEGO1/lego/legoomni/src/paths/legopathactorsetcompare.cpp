enum LegoEdgeFlag0 {
	c_edgeFlag0 = 1 << 0
};
class LegoPathRange0 {
public:
	int GetFirst() { return m_first; }
	int GetLast() { return m_last; }

private:
	int m_first;
	int m_last;
};
class LegoPathRange1 {
public:
	int GetFirst() { return m_first; }
	int GetLast() { return m_last; }

private:
	int m_first;
	int m_last;
};
class LegoPathRange2 {
public:
	int GetFirst() { return m_first; }
	int GetLast() { return m_last; }

private:
	int m_first;
	int m_last;
};
class LegoPathRange3 {
public:
	int GetFirst() { return m_first; }
	int GetLast() { return m_last; }

private:
	int m_first;
	int m_last;
};

#include "legopathboundary.h"

// This translation unit exists to supply ONE out-of-line member of the
// LegoPathActorSet red-black tree. Retail emits that member from a
// separate object, and it only reproduces byte-exactly when it is compiled in
// its own translation unit -- two of these members in one unit are never
// simultaneously exact. The declarations above the include are a stand-in for
// the 1997 source text that occupied this file; replace them if it is ever
// recovered.

// clang-format off
// MSVC 4.20 parses `>>` as a shift, so the closing angle brackets must stay split.
typedef _Tree<
	LegoPathActor*,
	LegoPathActor*,
	LegoPathActorSet::_Kfn,
	LegoPathActorSetCompare,
	allocator<LegoPathActor*>
> PathActorTree;
// clang-format on

struct PathActorInsertProbe : public PathActorTree {
	typedef iterator (PathActorTree::*Fn)(_Nodeptr, _Nodeptr, LegoPathActor* const&);
	static Fn Get();
};

PathActorInsertProbe::Fn PathActorInsertProbe::Get()
{
	return &PathActorTree::_Insert;
}
