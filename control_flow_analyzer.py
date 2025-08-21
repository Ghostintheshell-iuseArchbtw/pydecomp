#!/usr/bin/env python3
"""
Advanced Control Flow Analysis for Decompilation
Reconstructs high-level control structures from assembly code
"""

import re
import capstone
from typing import Dict, List, Tuple, Optional, Set, Any
from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum


class BlockType(Enum):
    """Types of basic blocks in control flow."""
    NORMAL = "normal"
    CONDITIONAL = "conditional"
    LOOP_HEADER = "loop_header"
    LOOP_BODY = "loop_body"
    LOOP_EXIT = "loop_exit"
    SWITCH_HEADER = "switch_header"
    SWITCH_CASE = "switch_case"
    FUNCTION_ENTRY = "function_entry"
    FUNCTION_EXIT = "function_exit"


@dataclass
class BasicBlock:
    """Represents a basic block in the control flow graph."""
    start_addr: int
    end_addr: int
    instructions: List[Any]
    predecessors: Set[int]
    successors: Set[int]
    block_type: BlockType = BlockType.NORMAL
    loop_depth: int = 0
    dominance_level: int = 0


@dataclass
class ControlStructure:
    """Represents a high-level control structure."""
    structure_type: str  # 'if', 'while', 'for', 'do-while', 'switch'
    header_block: int
    body_blocks: Set[int]
    exit_block: Optional[int] = None
    condition: Optional[str] = None
    nested_structures: List['ControlStructure'] = None


class ControlFlowAnalyzer:
    """Advanced control flow analysis for decompilation."""
    
    def __init__(self):
        self.basic_blocks: Dict[int, BasicBlock] = {}
        self.control_structures: List[ControlStructure] = []
        self.dominance_tree: Dict[int, Set[int]] = {}
        self.post_dominance_tree: Dict[int, Set[int]] = {}
        self.natural_loops: List[Dict[str, Any]] = []
        
        # Jump instruction patterns
        self.conditional_jumps = {
            'je', 'jz', 'jne', 'jnz', 'jl', 'jle', 'jg', 'jge',
            'ja', 'jae', 'jb', 'jbe', 'js', 'jns', 'jo', 'jno',
            'jp', 'jpe', 'jnp', 'jpo', 'jc', 'jnc', 'jecxz', 'jcxz'
        }
        
        self.unconditional_jumps = {'jmp', 'call', 'ret', 'retf', 'iret'}
        
    def analyze_function(self, instructions: List, start_addr: int) -> Dict[str, Any]:
        """Perform complete control flow analysis on a function."""
        if not instructions:
            return {'success': False, 'error': 'No instructions provided'}
            
        try:
            # Step 1: Build basic blocks
            self._build_basic_blocks(instructions, start_addr)
            
            # Step 2: Build control flow graph
            self._build_control_flow_graph()
            
            # Step 3: Compute dominance information
            self._compute_dominance()
            
            # Step 4: Detect natural loops
            self._detect_natural_loops()
            
            # Step 5: Identify control structures
            self._identify_control_structures()
            
            # Step 6: Generate high-level representation
            high_level_code = self._generate_high_level_code()
            
            return {
                'success': True,
                'basic_blocks': len(self.basic_blocks),
                'control_structures': len(self.control_structures),
                'natural_loops': len(self.natural_loops),
                'high_level_code': high_level_code,
                'complexity_metrics': self._calculate_complexity_metrics(),
                'cfg_analysis': self._analyze_cfg_properties()
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Control flow analysis failed: {str(e)}'}
            
    def _build_basic_blocks(self, instructions: List, start_addr: int):
        """Build basic blocks from instruction sequence."""
        if not instructions:
            return
            
        # Find all branch targets and fall-through points
        targets = set()
        targets.add(start_addr)  # Function entry is always a target
        
        current_addr = start_addr
        for i, inst in enumerate(instructions):
            if hasattr(inst, 'address'):
                current_addr = inst.address
            else:
                inst.address = current_addr
                current_addr += getattr(inst, 'size', 4)
                
            if hasattr(inst, 'mnemonic'):
                mnemonic = inst.mnemonic.lower()
                
                # Add targets for jump instructions
                if mnemonic in self.conditional_jumps or mnemonic in self.unconditional_jumps:
                    # Extract target address
                    target = self._extract_jump_target(inst)
                    if target:
                        targets.add(target)
                        
                    # Add fall-through target for conditional jumps
                    if mnemonic in self.conditional_jumps and i + 1 < len(instructions):
                        next_inst = instructions[i + 1]
                        if hasattr(next_inst, 'address'):
                            targets.add(next_inst.address)
                        else:
                            targets.add(current_addr)
                            
        # Sort targets for block creation
        sorted_targets = sorted(targets)
        
        # Create basic blocks
        for i, target in enumerate(sorted_targets):
            # Find instructions in this block
            block_instructions = []
            block_start = target
            
            # Determine block end
            if i + 1 < len(sorted_targets):
                block_end = sorted_targets[i + 1] - 1
            else:
                block_end = instructions[-1].address if instructions else target
                
            # Collect instructions for this block
            for inst in instructions:
                if hasattr(inst, 'address') and block_start <= inst.address <= block_end:
                    block_instructions.append(inst)
                    
            if block_instructions:
                block = BasicBlock(
                    start_addr=block_start,
                    end_addr=block_instructions[-1].address,
                    instructions=block_instructions,
                    predecessors=set(),
                    successors=set(),
                    block_type=BlockType.FUNCTION_ENTRY if block_start == start_addr else BlockType.NORMAL
                )
                
                self.basic_blocks[block_start] = block
                
    def _build_control_flow_graph(self):
        """Build edges between basic blocks."""
        for addr, block in self.basic_blocks.items():
            if not block.instructions:
                continue
                
            last_inst = block.instructions[-1]
            if not hasattr(last_inst, 'mnemonic'):
                continue
                
            mnemonic = last_inst.mnemonic.lower()
            
            if mnemonic in self.conditional_jumps:
                # Conditional jump: add both target and fall-through
                target = self._extract_jump_target(last_inst)
                if target and target in self.basic_blocks:
                    block.successors.add(target)
                    self.basic_blocks[target].predecessors.add(addr)
                    
                # Fall-through (next block in sequence)
                next_block = self._find_next_block(addr)
                if next_block:
                    block.successors.add(next_block)
                    self.basic_blocks[next_block].predecessors.add(addr)
                    
            elif mnemonic == 'jmp':
                # Unconditional jump
                target = self._extract_jump_target(last_inst)
                if target and target in self.basic_blocks:
                    block.successors.add(target)
                    self.basic_blocks[target].predecessors.add(addr)
                    
            elif mnemonic in ['ret', 'retf', 'iret']:
                # Function return - no successors
                block.block_type = BlockType.FUNCTION_EXIT
                
            else:
                # Normal fall-through
                next_block = self._find_next_block(addr)
                if next_block:
                    block.successors.add(next_block)
                    self.basic_blocks[next_block].predecessors.add(addr)
                    
    def _extract_jump_target(self, instruction) -> Optional[int]:
        """Extract jump target address from instruction."""
        if not hasattr(instruction, 'op_str'):
            return None
            
        op_str = instruction.op_str
        
        # Look for hexadecimal addresses
        hex_match = re.search(r'0x([0-9a-fA-F]+)', op_str)
        if hex_match:
            return int(hex_match.group(1), 16)
            
        # Look for decimal addresses
        dec_match = re.search(r'\b(\d+)\b', op_str)
        if dec_match:
            addr = int(dec_match.group(1))
            # Validate that this looks like a reasonable address
            if addr > 0x1000:  # Basic sanity check
                return addr
                
        return None
        
    def _find_next_block(self, current_addr: int) -> Optional[int]:
        """Find the next basic block in sequence."""
        sorted_addrs = sorted(self.basic_blocks.keys())
        try:
            current_idx = sorted_addrs.index(current_addr)
            if current_idx + 1 < len(sorted_addrs):
                return sorted_addrs[current_idx + 1]
        except ValueError:
            pass
        return None
        
    def _compute_dominance(self):
        """Compute dominance and post-dominance trees."""
        if not self.basic_blocks:
            return
            
        # Find entry and exit blocks
        entry_blocks = [addr for addr, block in self.basic_blocks.items() 
                       if block.block_type == BlockType.FUNCTION_ENTRY]
        exit_blocks = [addr for addr, block in self.basic_blocks.items() 
                      if block.block_type == BlockType.FUNCTION_EXIT]
                      
        if not entry_blocks:
            entry_blocks = [min(self.basic_blocks.keys())]
            
        # Compute dominance tree using iterative algorithm
        self.dominance_tree = self._compute_dominance_tree(entry_blocks[0], forward=True)
        
        if exit_blocks:
            self.post_dominance_tree = self._compute_dominance_tree(exit_blocks[0], forward=False)
            
    def _compute_dominance_tree(self, root: int, forward: bool = True) -> Dict[int, Set[int]]:
        """Compute dominance tree using standard algorithm."""
        nodes = set(self.basic_blocks.keys())
        dominance = {node: nodes.copy() for node in nodes}
        dominance[root] = {root}
        
        changed = True
        while changed:
            changed = False
            for node in nodes:
                if node == root:
                    continue
                    
                # Get predecessors or successors based on direction
                if forward:
                    preds = self.basic_blocks[node].predecessors
                else:
                    preds = self.basic_blocks[node].successors
                    
                if preds:
                    # Intersection of dominance sets of all predecessors
                    new_dom = set.intersection(*[dominance[pred] for pred in preds])
                    new_dom.add(node)
                else:
                    new_dom = {node}
                    
                if new_dom != dominance[node]:
                    dominance[node] = new_dom
                    changed = True
                    
        return dominance
        
    def _detect_natural_loops(self):
        """Detect natural loops using back edges."""
        self.natural_loops = []
        
        # Find back edges (edges from a block to one of its dominators)
        back_edges = []
        for addr, block in self.basic_blocks.items():
            for successor in block.successors:
                # Check if successor dominates current block
                if successor in self.dominance_tree.get(addr, set()):
                    back_edges.append((addr, successor))
                    
        # For each back edge, find the natural loop
        for tail, header in back_edges:
            loop_blocks = self._find_loop_blocks(header, tail)
            
            loop_info = {
                'header': header,
                'tail': tail,
                'blocks': loop_blocks,
                'loop_type': self._classify_loop_type(header, tail, loop_blocks),
                'nesting_level': self._compute_loop_nesting_level(header, loop_blocks)
            }
            
            self.natural_loops.append(loop_info)
            
            # Mark blocks as loop-related
            self.basic_blocks[header].block_type = BlockType.LOOP_HEADER
            for block_addr in loop_blocks:
                if block_addr != header:
                    self.basic_blocks[block_addr].block_type = BlockType.LOOP_BODY
                    
    def _find_loop_blocks(self, header: int, tail: int) -> Set[int]:
        """Find all blocks in the natural loop."""
        loop_blocks = {header, tail}
        
        # Traverse backwards from tail to header
        worklist = deque([tail])
        
        while worklist:
            current = worklist.popleft()
            
            for pred in self.basic_blocks[current].predecessors:
                if pred not in loop_blocks:
                    loop_blocks.add(pred)
                    if pred != header:  # Don't traverse beyond header
                        worklist.append(pred)
                        
        return loop_blocks
        
    def _classify_loop_type(self, header: int, tail: int, loop_blocks: Set[int]) -> str:
        """Classify the type of loop (while, for, do-while)."""
        header_block = self.basic_blocks[header]
        
        # Analyze the header block's last instruction
        if header_block.instructions:
            last_inst = header_block.instructions[-1]
            if hasattr(last_inst, 'mnemonic'):
                mnemonic = last_inst.mnemonic.lower()
                
                # If header ends with conditional jump, likely while/for
                if mnemonic in self.conditional_jumps:
                    # Check if there's a loop variable update pattern
                    if self._has_loop_variable_pattern(loop_blocks):
                        return 'for'
                    else:
                        return 'while'
                        
        # If header doesn't end with conditional, likely do-while
        if tail != header:
            tail_block = self.basic_blocks[tail]
            if tail_block.instructions:
                last_inst = tail_block.instructions[-1]
                if hasattr(last_inst, 'mnemonic') and last_inst.mnemonic.lower() in self.conditional_jumps:
                    return 'do-while'
                    
        return 'while'  # Default
        
    def _has_loop_variable_pattern(self, loop_blocks: Set[int]) -> bool:
        """Check if loop has a typical loop variable pattern."""
        # Look for increment/decrement patterns
        for block_addr in loop_blocks:
            block = self.basic_blocks[block_addr]
            for inst in block.instructions:
                if hasattr(inst, 'mnemonic'):
                    mnemonic = inst.mnemonic.lower()
                    if mnemonic in ['inc', 'dec', 'add', 'sub'] and 'esp' not in getattr(inst, 'op_str', ''):
                        return True
        return False
        
    def _compute_loop_nesting_level(self, header: int, loop_blocks: Set[int]) -> int:
        """Compute the nesting level of the loop."""
        nesting_level = 0
        
        # Count how many other loops contain this loop
        for other_loop in self.natural_loops:
            if other_loop['header'] != header:
                if header in other_loop['blocks'] and loop_blocks.issubset(other_loop['blocks']):
                    nesting_level += 1
                    
        return nesting_level
        
    def _identify_control_structures(self):
        """Identify high-level control structures."""
        self.control_structures = []
        
        # Identify if-else structures
        self._identify_if_else_structures()
        
        # Convert detected loops to control structures
        for loop in self.natural_loops:
            structure = ControlStructure(
                structure_type=loop['loop_type'],
                header_block=loop['header'],
                body_blocks=loop['blocks'],
                condition=self._extract_loop_condition(loop['header'])
            )
            self.control_structures.append(structure)
            
        # Identify switch statements
        self._identify_switch_statements()
        
    def _identify_if_else_structures(self):
        """Identify if-else control structures."""
        for addr, block in self.basic_blocks.items():
            if block.block_type != BlockType.LOOP_HEADER and len(block.successors) == 2:
                # Potential if-else structure
                successors = list(block.successors)
                
                # Find immediate post-dominator (merge point)
                merge_point = self._find_immediate_post_dominator(addr, successors)
                
                if merge_point:
                    # Classify branches
                    then_blocks = self._find_branch_blocks(successors[0], merge_point)
                    else_blocks = self._find_branch_blocks(successors[1], merge_point)
                    
                    structure = ControlStructure(
                        structure_type='if-else' if else_blocks else 'if',
                        header_block=addr,
                        body_blocks=then_blocks | else_blocks,
                        exit_block=merge_point,
                        condition=self._extract_branch_condition(block)
                    )
                    
                    self.control_structures.append(structure)
                    
    def _find_immediate_post_dominator(self, block_addr: int, successors: List[int]) -> Optional[int]:
        """Find the immediate post-dominator (merge point) of a conditional."""
        if not self.post_dominance_tree or block_addr not in self.post_dominance_tree:
            return None
            
        post_doms = self.post_dominance_tree[block_addr]
        
        # Find the closest post-dominator that's reachable from both successors
        for post_dom in sorted(post_doms):
            if post_dom != block_addr:
                # Check if both successors can reach this post-dominator
                if all(self._can_reach(succ, post_dom) for succ in successors):
                    return post_dom
                    
        return None
        
    def _can_reach(self, start: int, target: int) -> bool:
        """Check if start block can reach target block."""
        if start == target:
            return True
            
        visited = set()
        worklist = deque([start])
        
        while worklist:
            current = worklist.popleft()
            if current in visited:
                continue
            visited.add(current)
            
            if current == target:
                return True
                
            if current in self.basic_blocks:
                worklist.extend(self.basic_blocks[current].successors)
                
        return False
        
    def _find_branch_blocks(self, start: int, end: int) -> Set[int]:
        """Find all blocks in a branch from start to end."""
        blocks = set()
        visited = set()
        worklist = deque([start])
        
        while worklist:
            current = worklist.popleft()
            if current in visited or current == end:
                continue
            visited.add(current)
            blocks.add(current)
            
            if current in self.basic_blocks:
                worklist.extend(self.basic_blocks[current].successors)
                
        return blocks
        
    def _extract_branch_condition(self, block: BasicBlock) -> str:
        """Extract the condition from a conditional branch block."""
        if not block.instructions:
            return "unknown"
            
        last_inst = block.instructions[-1]
        if hasattr(last_inst, 'mnemonic') and last_inst.mnemonic.lower() in self.conditional_jumps:
            mnemonic = last_inst.mnemonic.lower()
            
            # Map jump mnemonics to conditions
            condition_map = {
                'je': '==', 'jz': '== 0',
                'jne': '!=', 'jnz': '!= 0',
                'jl': '<', 'jle': '<=',
                'jg': '>', 'jge': '>=',
                'ja': '> (unsigned)', 'jae': '>= (unsigned)',
                'jb': '< (unsigned)', 'jbe': '<= (unsigned)'
            }
            
            return condition_map.get(mnemonic, mnemonic)
            
        return "unknown"
        
    def _extract_loop_condition(self, header_addr: int) -> str:
        """Extract the loop condition from the header block."""
        if header_addr not in self.basic_blocks:
            return "unknown"
            
        return self._extract_branch_condition(self.basic_blocks[header_addr])
        
    def _identify_switch_statements(self):
        """Identify switch statement patterns."""
        for addr, block in self.basic_blocks.items():
            # Look for indirect jumps with many successors (jump tables)
            if len(block.successors) > 2 and block.instructions:
                last_inst = block.instructions[-1]
                if (hasattr(last_inst, 'mnemonic') and 
                    last_inst.mnemonic.lower() == 'jmp' and 
                    hasattr(last_inst, 'op_str') and 
                    '[' in last_inst.op_str):
                    
                    # This looks like a switch statement
                    structure = ControlStructure(
                        structure_type='switch',
                        header_block=addr,
                        body_blocks=block.successors.copy()
                    )
                    
                    self.control_structures.append(structure)
                    
                    # Mark successor blocks as switch cases
                    for successor in block.successors:
                        if successor in self.basic_blocks:
                            self.basic_blocks[successor].block_type = BlockType.SWITCH_CASE
                            
    def _generate_high_level_code(self) -> str:
        """Generate high-level pseudocode representation."""
        lines = []
        processed_blocks = set()
        
        # Find entry point
        entry_blocks = [addr for addr, block in self.basic_blocks.items() 
                       if block.block_type == BlockType.FUNCTION_ENTRY]
        
        if not entry_blocks:
            entry_blocks = [min(self.basic_blocks.keys())] if self.basic_blocks else []
            
        if entry_blocks:
            self._generate_block_code(entry_blocks[0], lines, processed_blocks, 0)
            
        return '\n'.join(lines)
        
    def _generate_block_code(self, block_addr: int, lines: List[str], 
                           processed_blocks: Set[int], indent_level: int):
        """Generate code for a basic block and its control structures."""
        if block_addr in processed_blocks or block_addr not in self.basic_blocks:
            return
            
        processed_blocks.add(block_addr)
        block = self.basic_blocks[block_addr]
        indent = "    " * indent_level
        
        # Check if this block is part of a control structure
        structure = self._find_containing_structure(block_addr)
        
        if structure and structure.header_block == block_addr:
            # Generate control structure code
            if structure.structure_type in ['while', 'for', 'do-while']:
                lines.append(f"{indent}{structure.structure_type} ({structure.condition}) {{")
                
                # Process loop body
                for body_block in sorted(structure.body_blocks):
                    if body_block != block_addr:  # Don't reprocess header
                        self._generate_block_code(body_block, lines, processed_blocks, indent_level + 1)
                        
                lines.append(f"{indent}}}")
                
            elif structure.structure_type == 'switch':
                lines.append(f"{indent}switch (variable) {{")
                
                for case_block in sorted(structure.body_blocks):
                    lines.append(f"{indent}    case value:")
                    self._generate_block_code(case_block, lines, processed_blocks, indent_level + 2)
                    lines.append(f"{indent}        break;")
                    
                lines.append(f"{indent}}}")
                
            elif structure.structure_type.startswith('if'):
                lines.append(f"{indent}if ({structure.condition}) {{")
                
                # Process body blocks
                for body_block in sorted(structure.body_blocks):
                    self._generate_block_code(body_block, lines, processed_blocks, indent_level + 1)
                    
                lines.append(f"{indent}}}")
                
        else:
            # Generate regular block code
            lines.append(f"{indent}// Block {block_addr:x}")
            
            # Add simplified instruction representations
            for inst in block.instructions:
                if hasattr(inst, 'mnemonic'):
                    simplified = self._simplify_instruction(inst)
                    if simplified:
                        lines.append(f"{indent}{simplified};")
                        
        # Process successors that aren't part of structures
        for successor in block.successors:
            if successor not in processed_blocks:
                structure = self._find_containing_structure(successor)
                if not structure or structure.header_block == successor:
                    self._generate_block_code(successor, lines, processed_blocks, indent_level)
                    
    def _find_containing_structure(self, block_addr: int) -> Optional[ControlStructure]:
        """Find the control structure containing this block."""
        for structure in self.control_structures:
            if block_addr in structure.body_blocks or block_addr == structure.header_block:
                return structure
        return None
        
    def _simplify_instruction(self, instruction) -> str:
        """Convert assembly instruction to simplified high-level equivalent."""
        if not hasattr(instruction, 'mnemonic'):
            return ""
            
        mnemonic = instruction.mnemonic.lower()
        op_str = getattr(instruction, 'op_str', '')
        
        # Simplify common patterns
        if mnemonic == 'mov':
            return f"assign({op_str})"
        elif mnemonic in ['add', 'sub', 'mul', 'imul', 'div', 'idiv']:
            return f"arithmetic({mnemonic}, {op_str})"
        elif mnemonic in ['cmp', 'test']:
            return f"compare({op_str})"
        elif mnemonic.startswith('j') and mnemonic != 'jmp':
            return f"conditional_jump({mnemonic}, {op_str})"
        elif mnemonic == 'call':
            return f"call_function({op_str})"
        elif mnemonic in ['ret', 'retf']:
            return "return"
        else:
            return f"{mnemonic}({op_str})"
            
    def _calculate_complexity_metrics(self) -> Dict[str, int]:
        """Calculate various complexity metrics."""
        metrics = {
            'cyclomatic_complexity': self._calculate_cyclomatic_complexity(),
            'basic_blocks': len(self.basic_blocks),
            'control_structures': len(self.control_structures),
            'loop_nesting_depth': self._calculate_max_loop_nesting(),
            'branch_factor': self._calculate_average_branch_factor()
        }
        
        return metrics
        
    def _calculate_cyclomatic_complexity(self) -> int:
        """Calculate McCabe cyclomatic complexity."""
        if not self.basic_blocks:
            return 1
            
        # V(G) = E - N + 2P
        # E = edges, N = nodes, P = connected components (assume 1)
        edges = sum(len(block.successors) for block in self.basic_blocks.values())
        nodes = len(self.basic_blocks)
        
        return edges - nodes + 2
        
    def _calculate_max_loop_nesting(self) -> int:
        """Calculate maximum loop nesting depth."""
        return max((loop['nesting_level'] for loop in self.natural_loops), default=0)
        
    def _calculate_average_branch_factor(self) -> int:
        """Calculate average branching factor."""
        if not self.basic_blocks:
            return 0
            
        total_successors = sum(len(block.successors) for block in self.basic_blocks.values())
        return total_successors // len(self.basic_blocks)
        
    def _analyze_cfg_properties(self) -> Dict[str, Any]:
        """Analyze control flow graph properties."""
        return {
            'is_reducible': self._is_reducible_graph(),
            'has_irreducible_loops': self._has_irreducible_loops(),
            'entry_blocks': len([b for b in self.basic_blocks.values() 
                               if b.block_type == BlockType.FUNCTION_ENTRY]),
            'exit_blocks': len([b for b in self.basic_blocks.values() 
                              if b.block_type == BlockType.FUNCTION_EXIT]),
            'unreachable_blocks': self._count_unreachable_blocks()
        }
        
    def _is_reducible_graph(self) -> bool:
        """Check if the control flow graph is reducible."""
        # Simplified check: if all loops are natural loops, graph is likely reducible
        return len(self.natural_loops) >= 0  # Placeholder implementation
        
    def _has_irreducible_loops(self) -> bool:
        """Check for irreducible loops."""
        # Placeholder implementation
        return False
        
    def _count_unreachable_blocks(self) -> int:
        """Count blocks that are unreachable from entry."""
        if not self.basic_blocks:
            return 0
            
        entry_blocks = [addr for addr, block in self.basic_blocks.items() 
                       if block.block_type == BlockType.FUNCTION_ENTRY]
        
        if not entry_blocks:
            return 0
            
        # BFS from entry to find reachable blocks
        reachable = set()
        worklist = deque(entry_blocks)
        
        while worklist:
            current = worklist.popleft()
            if current in reachable:
                continue
            reachable.add(current)
            
            if current in self.basic_blocks:
                worklist.extend(self.basic_blocks[current].successors)
                
        return len(self.basic_blocks) - len(reachable)