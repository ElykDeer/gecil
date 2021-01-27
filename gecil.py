#!/usr/bin/env python3

from lark import Lark, Visitor, Token
import hlil


class SourceToHLILVisitor(Visitor):

  def __init__(self, func):
    super().__init__()
    self.function = func
    self.memory = ""  # TODO : This should really be a byte array, but damn is it late
    # self.memory = bytearray()
    self.current_block = None

  # def parameters(self, tokens):
  #   return tokens

  # def parameter(self, tokens):
  #   return tokens

  # def variable_name(self, tokens):
  #   return tokens

  def basic_block(self, tokens):
    self.current_block = self.function.new_basic_block()

  # def function_definition(self, tokens):
  #   return tokens

  # def statement(self, tokens):
  #   return tokens

  def comment(self, tokens):
    self.current_block.append_instruction(hlil.HighLevelILOperation.HLIL_COMMENT, value=tokens.children[0].value.strip())

  def function_call(self, tokens):
    target_symbol = tokens.children[0].value
    symbol_address = len(self.memory)
    self.memory += target_symbol + "\x00"

    target_arg = tokens.children[1].children[0].children[0].value
    arg_address = len(self.memory)
    self.memory += target_arg + "\x00"

    # This is where it'd be nice to do the bottom-up approach and create arbitrary IL instruction that get stitched together...shrug
    self.current_block.append_instruction(hlil.HighLevelILOperation.HLIL_CALL,
      operands =
        [(hlil.HighLevelILOperation.HLIL_CONST_PTR, symbol_address, None, [symbol_address]),
        (hlil.HighLevelILOperation.HLIL_CONST_PTR, arg_address, None, [arg_address])]
      )

  def return_statement(self, tokens):
    self.current_block.append_instruction(hlil.HighLevelILOperation.HLIL_RET)


def gecil(source):
  with open("gecil.lark", "r") as f:
    parser = Lark(f.read())

  source_tree = parser.parse(source)
  if __name__ == "__main__":
    print("Source tree:\n", source_tree.pretty())

  function_name = source_tree.children[0].children[1].children[0].value
  func = hlil.HighLevelILFunction(function_name)
  transformer = SourceToHLILVisitor(func)
  hlil_tree = transformer.visit_topdown(source_tree)  # Topdown is a horrible way to do this....I should write a transformer to transform my AST to a HLIL-compatible tree, then visit that tree top-down to emit HLIL....but this toy example can skip all that

  return func, transformer.memory


if __name__ == "__main__":
  gecil("""
int main()
{
  // printf takes a format string and prints it to standard out
  printf("Hello world!");

  // return 0 means that we ran correctly and have no errors
  return 0;
}
""")
