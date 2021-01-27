###############################################################################################################
# Ignore this file, it's a bunch of plumbing and garbage to allow the "creation" of HLIL without a BV to work #
###############################################################################################################


from enum import Enum


class HighLevelILOperation(Enum):
	HLIL_BLOCK = 1
	HLIL_IF = 2
	HLIL_WHILE = 3
	HLIL_DO_WHILE = 4
	HLIL_FOR = 5
	HLIL_SWITCH = 6
	HLIL_CASE = 7
	HLIL_BREAK = 8
	HLIL_CONTINUE = 9
	HLIL_JUMP = 10
	HLIL_RET = 11
	HLIL_VAR_DECLARE = 12
	HLIL_VAR_INIT = 13
	HLIL_ASSIGN = 14
	HLIL_ASSIGN_UNPACK = 15
	HLIL_VAR = 16
	HLIL_STRUCT_FIELD = 17
	HLIL_ARRAY_INDEX = 18
	HLIL_SPLIT = 19
	HLIL_DEREF = 20
	HLIL_DEREF_FIELD = 21
	HLIL_ADDRESS_OF = 22
	HLIL_CONST = 23
	HLIL_CONST_PTR = 24
	HLIL_FLOAT_CONST = 25
	HLIL_ADD = 26
	HLIL_ADC = 27
	HLIL_SUB = 28
	HLIL_SBB = 29
	HLIL_AND = 30
	HLIL_OR = 31
	HLIL_XOR = 32
	HLIL_LSL = 33
	HLIL_LSR = 34
	HLIL_ASR = 35
	HLIL_ROL = 36
	HLIL_RLC = 37
	HLIL_ROR = 38
	HLIL_RRC = 39
	HLIL_MUL = 40
	HLIL_MULU_DP = 41
	HLIL_MULS_DP = 42
	HLIL_DIVU = 43
	HLIL_DIVU_DP = 44
	HLIL_DIVS = 45
	HLIL_DIVS_DP = 46
	HLIL_MODU = 47
	HLIL_MODU_DP = 48
	HLIL_MODS = 49
	HLIL_MODS_DP = 50
	HLIL_NEG = 51
	HLIL_NOT = 52
	HLIL_CALL = 53
	HLIL_CMP_E = 54
	HLIL_CMP_NE = 55
	HLIL_CMP_SLT = 56
	HLIL_CMP_ULT = 57
	HLIL_CMP_SLE = 58
	HLIL_CMP_ULE = 59
	HLIL_CMP_SGE = 60
	HLIL_CMP_UGE = 61
	HLIL_CMP_SGT = 62
	HLIL_CMP_UGT = 63
	HLIL_FLOOR = 64
	HLIL_CEIL = 65
	HLIL_COMMENT = 66


class HighLevelILInstruction():
	ILOperations = {
		HighLevelILOperation.HLIL_BLOCK: [("body", "expr_list")],
		HighLevelILOperation.HLIL_IF: [("condition", "expr"), ("true", "expr"), ("false", "expr")],
		HighLevelILOperation.HLIL_WHILE: [("condition", "expr"), ("body", "expr")],
		HighLevelILOperation.HLIL_DO_WHILE: [("body", "expr"), ("condition", "expr")],
		HighLevelILOperation.HLIL_FOR: [("init", "expr"), ("condition", "expr"), ("update", "expr"), ("body", "expr")],
		HighLevelILOperation.HLIL_SWITCH: [("condition", "expr"), ("default", "expr"), ("cases", "expr_list")],
		HighLevelILOperation.HLIL_CASE: [("values", "expr_list"), ("body", "expr")],
		HighLevelILOperation.HLIL_BREAK: [],
		HighLevelILOperation.HLIL_CONTINUE: [],
		HighLevelILOperation.HLIL_JUMP: [("dest", "expr")],
		HighLevelILOperation.HLIL_RET: [("src", "expr_list")],
		HighLevelILOperation.HLIL_VAR_DECLARE: [("var", "var")],
		HighLevelILOperation.HLIL_VAR_INIT: [("dest", "var"), ("src", "expr")],
		HighLevelILOperation.HLIL_ASSIGN: [("dest", "expr"), ("src", "expr")],
		HighLevelILOperation.HLIL_ASSIGN_UNPACK: [("dest", "expr_list"), ("src", "expr")],
		HighLevelILOperation.HLIL_VAR: [("var", "var")],
		HighLevelILOperation.HLIL_STRUCT_FIELD: [("src", "expr"), ("offset", "int"), ("member_index", "member_index")],
		HighLevelILOperation.HLIL_ARRAY_INDEX: [("src", "expr"), ("index", "expr")],
		HighLevelILOperation.HLIL_SPLIT: [("high", "expr"), ("low", "expr")],
		HighLevelILOperation.HLIL_DEREF: [("src", "expr")],
		HighLevelILOperation.HLIL_DEREF_FIELD: [("src", "expr"), ("offset", "int"), ("member_index", "member_index")],
		HighLevelILOperation.HLIL_ADDRESS_OF: [("src", "expr")],
		HighLevelILOperation.HLIL_CONST: [("constant", "int")],
		HighLevelILOperation.HLIL_CONST_PTR: [("constant", "int")],
		HighLevelILOperation.HLIL_FLOAT_CONST: [("constant", "float")],
		HighLevelILOperation.HLIL_ADD: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_ADC: [("left", "expr"), ("right", "expr"), ("carry", "expr")],
		HighLevelILOperation.HLIL_SUB: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_SBB: [("left", "expr"), ("right", "expr"), ("carry", "expr")],
		HighLevelILOperation.HLIL_AND: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_OR: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_XOR: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_LSL: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_LSR: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_ASR: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_ROL: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_RLC: [("left", "expr"), ("right", "expr"), ("carry", "expr")],
		HighLevelILOperation.HLIL_ROR: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_RRC: [("left", "expr"), ("right", "expr"), ("carry", "expr")],
		HighLevelILOperation.HLIL_MUL: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_MULU_DP: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_MULS_DP: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_DIVU: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_DIVU_DP: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_DIVS: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_DIVS_DP: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_MODU: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_MODU_DP: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_MODS: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_MODS_DP: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_NEG: [("src", "expr")],
		HighLevelILOperation.HLIL_NOT: [("src", "expr")],
		HighLevelILOperation.HLIL_CALL: [("dest", "expr"), ("params", "expr_list")],
		HighLevelILOperation.HLIL_CMP_E: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_CMP_NE: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_CMP_SLT: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_CMP_ULT: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_CMP_SLE: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_CMP_ULE: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_CMP_SGE: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_CMP_UGE: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_CMP_SGT: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_CMP_UGT: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_FLOOR: [("src", "expr")],
		HighLevelILOperation.HLIL_CEIL: [("src", "expr")],
		HighLevelILOperation.HLIL_COMMENT: [],
	}

	def __init__(self, func, expr_index, instr_index, operation, value, source_operand, operands, parent):
		self._function = func
		self._expr_index = expr_index
		self._instr_index = instr_index
		self._operation = operation
		self._value = value
		self._source_operand = source_operand
		self._parent = parent
		self._operands = []

		expected_operands = HighLevelILInstruction.ILOperations[operation]
		i = 0
		for operand in expected_operands:
			name, operand_type = operand
			value = None
			if operand_type == "int":
				value = operands[i]
				value = (value & ((1 << 63) - 1)) - (value & (1 << 63))
			elif operand_type == "expr":
				operation, value, source_operand, sub_operands = operands[i]
				value = HighLevelILInstruction(self._function, self._function.new_expr_index(), instr_index, operation, value, source_operand, sub_operands, self)
			# elif operand_type == "var":
			# 	value =
			# elif operand_type == "int_list":
			# 	operand_list = core.BNHighLevelILGetOperandList(func.handle, self._expr_index, i, count)
			# 	value = []
			# 	for j in range(count.value):
			# 		value.append(operand_list[j])
			# 	core.BNHighLevelILFreeOperandList(operand_list)
			elif operand_type == "expr_list" and isinstance(operands, list):
				# TODO : Parse multiple exprs in a list
				operation, value, source_operand, sub_operands = operands[i]
				value = HighLevelILInstruction(self._function, self._function.new_expr_index(), instr_index, operation, value, source_operand, sub_operands, self)
			elif operand_type == "member_index":
				value = operands[i]
				if (value & (1 << 63)) != 0:
					value = None
			self._operands.append(value)
			self.__dict__[name] = value
			i += 1

	def __str__(self):
		lines = self.lines
		if lines is None:
			return "invalid"
		return '\n'.join(lines)

	def __repr__(self):
		lines = self.lines
		continuation = ""
		if lines is None:
			first_line = "<invalid>"
		else:
			first_line = ""
			for token in lines[0].tokens:
				first_line += token.text
			if len(lines) > 1:
				continuation = "..."
		return "<%s: %s%s>" % (self._operation.name, first_line, continuation)

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self._function, self._expr_index, self._operation, self._source_operand, self._size, self._operands, self._parent) == (other._function, other._expr_index, other._operation, other._source_operand, other._size, other._operands, other._parent)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	@property
	def lines(self):
		"""HLIL text lines (read-only)"""
		if self._operation == HighLevelILOperation.HLIL_COMMENT:
			return [f"// {self._value}"]
		elif self._operation == HighLevelILOperation.HLIL_RET:
			return ["return"]
		elif self._operation == HighLevelILOperation.HLIL_BLOCK:
			return None
		else:
			return None


	@property
	def prefix_operands(self):
		"""All operands in the expression tree in prefix order"""
		result = []
		for operand in self._operands:
			if isinstance(operand, HighLevelILInstruction):
				result += operand.prefix_operands
			else:
				result.append(operand)
		return result

	@property
	def postfix_operands(self):
		"""All operands in the expression tree in postfix order"""
		result = []
		for operand in self._operands:
			if isinstance(operand, HighLevelILInstruction):
				result += operand.postfix_operands
			else:
				result.append(operand)
		return result

	@property
	def function(self):
		""" """
		return self._function

	@property
	def expr_index(self):
		""" """
		return self._expr_index

	@property
	def instr_index(self):
		"""Index of the statement that this expression belongs to (read-only)"""
		return self.instr_index

	@property
	def instr(self):
		"""The statement that this expression belongs to (read-only)"""
		return self._function[self.instr_index]

	@property
	def operation(self):
		""" """
		return self._operation

	@property
	def source_operand(self):
		""" """
		return self._source_operand

	@property
	def operands(self):
		""" """
		return self._operands

	@property
	def parent(self):
		return self._parent

	# @property
	# def il_basic_block(self):
	# 	"""
	# 	IL basic block object containing this expression (read-only) (only available on finalized functions).
	# 	Returns None for HLIL_BLOCK expressions as these can contain multiple basic blocks.
	# 	"""
	# 	block = core.BNGetHighLevelILBasicBlockForInstruction(self._function.handle, self._instr_index)
	# 	if not block:
	# 		return None
	# 	return HighLevelILBasicBlock(self._function.source_function.view, block, self._function)

	@property
	def value(self):
		"""Value of expression if constant or a known value (read-only)"""
		return self._value

	# @property
	# def possible_values(self):
		# """Possible values of expression using path-sensitive static data flow analysis (read-only)"""
		# mlil = self.mlil
		# if mlil is None:
		# 	return function.PossibleValueSet()
		# return mlil.possible_values

	# @property
	# def expr_type(self):
	# 	"""Type of expression"""
	# 	result = core.BNGetHighLevelILExprType(self._function.handle, self._expr_index)
	# 	if result.type:
	# 		platform = None
	# 		if self._function.source_function:
	# 			platform = self._function.source_function.platform
	# 		return types.Type(result.type, platform = platform, confidence = result.confidence)
	# 	return None

	# def get_possible_values(self, options = []):
	# 	mlil = self.mlil
	# 	if mlil is None:
	# 		return function.RegisterValue()
	# 	return mlil.get_possible_values(options)


class BranchType(Enum):
	UnconditionalBranch = 0
	FalseBranch = 1
	TrueBranch = 2
	CallDestination = 3
	FunctionReturn = 4
	SystemCall = 5
	IndirectBranch = 6
	ExceptionBranch = 7
	UnresolvedBranch = 127
	UserDefinedBranch = 128


class BasicBlockEdge():
	def __init__(self, branch_type, source_block, target_block, back_edge):
		self._type = branch_type
		self._source_block = source_block
		self._target_block = target_block
		self._back_edge = back_edge

	def __repr__(self):
		if self._type == BranchType.UnresolvedBranch:
			return "<%s>" % BranchType(self._type).name
		else:
			return "<%s: %#x>" % (BranchType(self._type).name, self._target_block.start)

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self._type, self._source_block, self._target_block, self._back_edge) == \
			(other._type, other._source, other._target, other._back_edge)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	@property
	def type(self):
		""" """
		return self._type

	@type.setter
	def type(self, value):
		self._type = value

	@property
	def target(self):
		""" """
		return self._target_block

	@target.setter
	def target(self, value):
		self._target_block = value

	@property
	def back_edge(self):
		""" """
		return self._back_edge

	@back_edge.setter
	def back_edge(self, value):
		self._back_edge = value


class BasicBlock():
	def __init__(self, start = 0, function = None):
		self.func = function
		self.il = []
		self._start = start
		self._end = start

	def __repr__(self):
		return "<block: %#x-%#x>" % (self.start, self.end)

	def __len__(self):
		return len(self.il)

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		for my_il, their_il in zip(self.il, other.il):
			if my_il != their_il:
				return False
		return True

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __iter__(self):
		for il in self.il:
			yield il

	def __getitem__(self, i):
		return self.il[i-self._start]

	def append_instruction(self, operation, value = None, source_operand = None, operands = None, parent = None):
		self.il.append(HighLevelILInstruction(self.func, self.function.new_expr_index(), self._start + len(self.il), operation, value, source_operand, operands, parent))

	@property
	def instruction_count(self):
		return len(self.il)

	@property
	def function(self):
		if self.func is None:
			return None
		return self.func

	@property
	def start(self):
		self._start

	@property
	def end(self):
		self._end

	@property
	def length(self):
		return len(self.il)

	# @property
	# def index(self):
	# 	"""Basic block index in list of blocks for the function (read-only)"""

	# @property
	# def outgoing_edges(self):
	# 	"""List of basic block outgoing edges (read-only)"""
	# 	count = ctypes.c_ulonglong(0)
	# 	edges = core.BNGetBasicBlockOutgoingEdges(self.handle, count)
	# 	result = []
	# 	for i in range(0, count.value):
	# 		branch_type = BranchType(edges[i].type)
	# 		if edges[i].target:
	# 			target = self._create_instance(core.BNNewBasicBlockReference(edges[i].target), self.view)
	# 		else:
	# 			target = None
	# 		result.append(BasicBlockEdge(branch_type, self, target, edges[i].backEdge, edges[i].fallThrough))
	# 	core.BNFreeBasicBlockEdgeList(edges, count.value)
	# 	return result

	# @property
	# def incoming_edges(self):
	# 	"""List of basic block incoming edges (read-only)"""
	# 	count = ctypes.c_ulonglong(0)
	# 	edges = core.BNGetBasicBlockIncomingEdges(self.handle, count)
	# 	result = []
	# 	for i in range(0, count.value):
	# 		branch_type = BranchType(edges[i].type)
	# 		if edges[i].target:
	# 			target = self._create_instance(core.BNNewBasicBlockReference(edges[i].target), self.view)
	# 		else:
	# 			target = None
	# 		result.append(BasicBlockEdge(branch_type, target, self, edges[i].backEdge, edges[i].fallThrough))
	# 	core.BNFreeBasicBlockEdgeList(edges, count.value)
	# 	return result


class HighLevelILFunction():
	def __init__(self, name = None):
		self.name = name
		self.bbs = []
		self.expr_index = 0

	# def __eq__(self, other):
	# 	if not isinstance(other, self.__class__):
	# 		return NotImplemented
	# 	return ctypes.addressof(self.handle.contents) == ctypes.addressof(other.handle.contents)

	# def __ne__(self, other):
	# 	if not isinstance(other, self.__class__):
	# 		return NotImplemented
	# 	return not (self == other)

	def new_basic_block(self):
		new_block = BasicBlock(function=self)
		self.bbs.append(new_block)
		return new_block

	def new_expr_index(self):
		self.expr_index += 1
		return self.expr_index - 1

	@property
	def root(self):
		if len(self.bbs) == 0:
			return None
		return self.bbs[0]

	@property
	def basic_blocks(self):
		for block in self.bbs:
			yield block

	@property
	def instructions(self):
		for block in self.bbs:
			for il in block:
				yield il

	# def get_var_definitions(self, var):
	# 	count = ctypes.c_ulonglong()
	# 	var_data = core.BNVariable()
	# 	var_data.type = var.source_type
	# 	var_data.index = var.index
	# 	var_data.storage = var.storage
	# 	instrs = core.BNGetHighLevelILVariableDefinitions(self.handle, var_data, count)
	# 	result = []
	# 	for i in range(0, count.value):
	# 		result.append(HighLevelILInstruction(self, instrs[i]))
	# 	core.BNFreeILInstructionList(instrs)
	# 	return result

	# def get_var_uses(self, var):
	# 	count = ctypes.c_ulonglong()
	# 	var_data = core.BNVariable()
	# 	var_data.type = var.source_type
	# 	var_data.index = var.index
	# 	var_data.storage = var.storage
	# 	instrs = core.BNGetHighLevelILVariableUses(self.handle, var_data, count)
	# 	result = []
	# 	for i in range(0, count.value):
	# 		result.append(HighLevelILInstruction(self, instrs[i]))
	# 	core.BNFreeILInstructionList(instrs)
	# 	return result

	def __len__(self):
		return sum([c.count for c in self.bbs])

	# def __getitem__(self, i):
	# 	if isinstance(i, slice) or isinstance(i, tuple):
	# 		raise IndexError("expected integer instruction index")
	# 	if isinstance(i, HighLevelILExpr):
	# 		return HighLevelILInstruction(self, i.index)
	# 	# for backwards compatibility
	# 	if isinstance(i, HighLevelILInstruction):
	# 		return i
	# 	if i < -len(self) or i >= len(self):
	# 		raise IndexError("index out of range")
	# 	if i < 0:
	# 		i = len(self) + i
	# 	return HighLevelILInstruction(self, core.BNGetHighLevelILIndexForInstruction(self.handle, i), False, i)

	def __iter__(self):
		for block in self.bbs:
			for il in block:
				yield il

	def __str__(self):
		return str(self.root)

	# def expr(self, operation, a = 0, b = 0, c = 0, d = 0, e = 0, size = 0):
	# 	if isinstance(operation, str):
	# 		operation = HighLevelILOperation[operation]
	# 	elif isinstance(operation, HighLevelILOperation):
	# 		operation = operation.value
	# 	return HighLevelILExpr(core.BNHighLevelILAddExpr(self.handle, operation, size, a, b, c, d, e))

	# def create_graph(self, settings = None):
	# 	if settings is not None:
	# 		settings_obj = settings.handle
	# 	else:
	# 		settings_obj = None
	# 	return binaryninja.flowgraph.CoreFlowGraph(core.BNCreateHighLevelILFunctionGraph(self.handle, settings_obj))
