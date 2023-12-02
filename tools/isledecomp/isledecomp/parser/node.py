from dataclasses import dataclass


@dataclass
class ParserNode:
    line_number: int


@dataclass
class ParserAlert(ParserNode):
    code: int
    line: str


@dataclass
class ParserSymbol(ParserNode):
    module: str
    offset: int


@dataclass
class ParserFunction(ParserSymbol):
    name: str
    lookup_by_name: bool = False
    is_stub: bool = False
    is_synthetic: bool = False
    is_template: bool = False
    end_line: int = -1


@dataclass
class ParserVariable(ParserSymbol):
    name: str
    size: int = -1
    is_static: bool = False


@dataclass
class ParserVtable(ParserSymbol):
    class_name: str
    num_entries: int = -1
