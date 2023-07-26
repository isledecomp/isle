#include "mxbinarytree.h"

// 0x101013f0
TreeNode *MxBinaryTree::g_Node_Nil = NULL;

// OFFSET: LEGO1 0x100ad170
TreeValue::~TreeValue()
{
  // nothing.
}

inline void MxBinaryTree::LeftRotate(TreeNode *x)
{
  TreeNode *y = x->m_child1;
  x->m_child1 = y->m_child0;
  
  if (y->m_child0 != g_Node_Nil)
    y->m_child0->m_parent = x;

  y->m_parent = x->m_parent;

  if (m_root->m_parent != x) {
    if (x != x->m_parent->m_child0) {
      x->m_parent->m_child1 = y;
      y->m_child0 = x;
      x->m_parent = y;
    } else {
      x->m_parent->m_child0 = y;
      y->m_child0 = x;
      x->m_parent = y;
    }
  } else {
    m_root->m_parent->m_child0 = y;
    y->m_child0 = x;
    x->m_parent = y;
  }
}

inline void MxBinaryTree::RightRotate(TreeNode *x)
{
  TreeNode *y = x->m_child0;
  x->m_child0 = y->m_child1;
  
  if (y->m_child1 != g_Node_Nil)
    y->m_child1->m_parent = x;

  y->m_parent = x->m_parent;

  if (m_root->m_parent != x) {
    if (x != x->m_parent->m_child1) {
      x->m_parent->m_child0 = y;
      y->m_child1 = x;
      x->m_parent = y;
    } else {
      x->m_parent->m_child1 = y;
      y->m_child1 = x;
      x->m_parent = y;
    }
  } else {
    m_root->m_parent->m_child1 = y;
    y->m_child1 = x;
    x->m_parent = y;
  }
}

// OFFSET: LEGO1 0x100ad480
void mini_walk(TreeNode* &p_node)
{
  if (p_node->m_color == NODE_COLOR_RED
      && p_node->m_parent->m_parent == p_node) {
    p_node = p_node->m_child1;
    return;
  }

  TreeNode *t = p_node->m_child0;
  if (t != MxBinaryTree::g_Node_Nil) {
    
    // wonky
    while (1) {
      if (t->m_child1 == MxBinaryTree::g_Node_Nil)
        break;
      t = t->m_child1;
    }
    
    p_node = t;
    return;
  }

  TreeNode *u = p_node->m_parent;
  TreeNode *v = p_node;
  while (u != v) {
    p_node = u;
    v = u;
    u = u->m_parent;
  }

  p_node = u;
}

// OFFSET: LEGO1 0x100ad4d0
void MxBinaryTree::Insert(TreeNode **p_output, TreeNode *p_leaf, TreeNode *p_parent, TreeValue *&p_value)
{
  TreeNode *node = newTreeNode(p_parent, NODE_COLOR_RED);
  node->m_child0 = g_Node_Nil;
  node->m_child1 = g_Node_Nil;
  
  // TODO: ???
  if (&node->m_value)
    node->m_value = p_value;

  this->m_nodeCount++;

  // if tree is NOT empty
  // if param_2 is tree_nil (always true I think?)
  //
  if (m_root != p_parent
      && p_leaf == MxBinaryTree::g_Node_Nil
      && TreeValueCompare(p_value, p_parent->m_value)) {
    p_parent->m_child1 = node;
    
    if (m_root->m_child1 == p_parent)
      m_root->m_child1 = node;
  } else {
    p_parent->m_child0 = node;

    if (m_root != p_parent) {
      if (m_root->m_child0 == p_parent)
        m_root->m_child0 = node;
    } else {
      m_root->m_parent = node;
      m_root->m_child1 = node;
    }
  }

  // LAB_100ad593
  // rebalance the tree
  TreeNode *cur = node;
  while (m_root->m_parent != cur) {
    TreeNode *parent = cur->m_parent;

    if (parent->m_color != NODE_COLOR_RED)
      break;

    TreeNode *uncle = parent->m_parent->m_child0;
    if (uncle == parent) {
      // wrong uncle
      uncle = parent->m_parent->m_child1;

      if (uncle->m_color != NODE_COLOR_RED) {
        
        // 100ad5d3
        if (parent->m_child1 == cur) {
          cur = parent;
          LeftRotate(cur);
        }

        // LAB_100ad60f
        cur->m_parent->m_color = NODE_COLOR_BLACK;
        cur->m_parent->m_parent->m_color = NODE_COLOR_RED;
        RightRotate(cur->m_parent->m_parent);
        continue;
      }
    } else {
      // LAB_100ad67f
      if (uncle->m_color != NODE_COLOR_RED) {
        if (parent->m_child0 == cur) {
          cur = parent;
          RightRotate(cur);
        }

        // LAB_100ad60f
        cur->m_parent->m_color = NODE_COLOR_BLACK;
        cur->m_parent->m_parent->m_color = NODE_COLOR_RED;
        LeftRotate(cur->m_parent->m_parent);
        continue;
      }
    }

    // LAB_100ad72c
    parent->m_color = NODE_COLOR_BLACK;
    uncle->m_color = NODE_COLOR_BLACK;
    parent->m_parent->m_color = NODE_COLOR_RED;

    cur = parent->m_parent;
  }

  m_root->m_parent->m_color = NODE_COLOR_BLACK;
  *p_output = node;
}

// OFFSET: LEGO1 0x100ad780
TreeNode *MxBinaryTree::Search(TreeValue*& p_value)
{
  TreeNode *node_match = m_root;
  TreeNode *t_node = node_match->m_parent;
  
  while (t_node != g_Node_Nil) {
    if (!TreeValueCompare(t_node->m_value, p_value)) {
      // closest match?
      // it either does match or is where we will insert the new node.
      node_match = t_node;
      t_node = t_node->m_child0;
    } else {
      t_node = t_node->m_child1;
    }
  }

  return node_match;
}

// OFFSET: LEGO1 0x100ad7f0
void TreeValue::RefCountInc()
{
  m_t0++;
}

// OFFSET: LEGO1 0x100ad800
void TreeValue::RefCountDec()
{
  if (m_t0)
    m_t0--;
}
