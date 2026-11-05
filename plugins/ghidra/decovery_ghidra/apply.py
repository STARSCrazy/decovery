"""`analyzer/apply`: put decovery knowledge (names, signatures, comments, locals, line comments, `types.h`,
references) into the Ghidra program.

The parameter parsing and the C text helpers are pure Python; `GhidraApplier` holds the Ghidra calls (imports are
local to its methods). Ported from Decomp's Ghidra engine (`wissen_anwenden`, `_aufraeumen`, `_symbol_anwenden`,
`_lokal`, `_verweise_anwenden`, `_structs_nach_offsets`, `_aufrufart_setzen`): same Ghidra classes, same
transaction handling. Per-item problems become warnings; nothing here fails the whole call.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import mapping
from .export import write_atomic
from .mapping import GhidraAddress

SYMBOL_KINDS = ("function", "global", "label")
REFERENCE_KINDS = ("call", "jump")


class ParamsError(ValueError):
    """The apply params are malformed as a whole (not a single item)."""


@dataclass(frozen=True)
class ApplyLocal:
    place: str  # `param:1`, `stack:-0x14`, `reg:ax`
    name: str
    data_type: str | None = None


@dataclass(frozen=True)
class ApplyLineComment:
    address: GhidraAddress
    text: str


@dataclass(frozen=True)
class ApplySymbol:
    address: GhidraAddress
    label: str  # decovery address (and name) for warnings
    kind: str
    name: str | None = None
    signature: str | None = None
    comment: str | None = None
    data_type: str | None = None
    locals: list[ApplyLocal] = field(default_factory=list)
    line_comments: list[ApplyLineComment] = field(default_factory=list)


@dataclass(frozen=True)
class ApplyReference:
    from_: GhidraAddress
    to: GhidraAddress
    kind: str  # "call" | "jump"
    label: str


# -- parameter parsing (pure) ----------------------------------------------------------------------------------


def _optional_text(raw: dict, key: str) -> str | None:
    value = raw.get(key)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"'{key}' must be a string")
    return value


def _parse_symbol(raw: Any, arch: str, warnings: list[str], label: str) -> ApplySymbol:
    if not isinstance(raw, dict):
        raise ValueError("not an object")
    if "address" not in raw:
        raise ValueError("missing 'address'")
    address = mapping.to_ghidra_address(raw["address"], arch)
    kind = raw.get("kind")
    if kind not in SYMBOL_KINDS:
        raise ValueError(f"unknown kind {kind!r} (known: {', '.join(SYMBOL_KINDS)})")
    locals_ = []
    for index, local in enumerate(raw.get("locals") or []):
        what = local.get("name") if isinstance(local, dict) else None
        try:
            if not isinstance(local, dict):
                raise ValueError("not an object")
            place, name = local.get("place"), local.get("name")
            if not isinstance(place, str) or not place:
                raise ValueError("missing 'place'")
            if not isinstance(name, str) or not name:
                raise ValueError("missing 'name'")
            locals_.append(ApplyLocal(place, name, _optional_text(local, "data_type")))
        except ValueError as exc:
            warnings.append(f"{label}: local {what or index}: {exc}")
    line_comments = []
    for index, comment in enumerate(raw.get("line_comments") or []):
        what = comment.get("address") if isinstance(comment, dict) else None
        try:
            if not isinstance(comment, dict):
                raise ValueError("not an object")
            text = comment.get("text")
            if not isinstance(text, str):
                raise ValueError("missing 'text'")
            line_comments.append(ApplyLineComment(mapping.to_ghidra_address(comment.get("address"), arch), text))
        except ValueError as exc:  # MappingError is a ValueError
            warnings.append(f"{label}: line comment {what!r} ({index}): {exc}")
    return ApplySymbol(
        address=address,
        label=label,
        kind=kind,
        name=_optional_text(raw, "name"),
        signature=_optional_text(raw, "signature"),
        comment=_optional_text(raw, "comment"),
        data_type=_optional_text(raw, "data_type"),
        locals=locals_,
        line_comments=line_comments,
    )


def parse_apply_params(
    params: dict, arch: str
) -> tuple[list[ApplySymbol], str, list[ApplyReference], list[str]]:
    """Symbols, `types.h` text, references and the warnings for items that were skipped."""
    symbols_raw = params.get("symbols", [])
    types_h = params.get("types_h", "")
    references_raw = params.get("references", [])
    if not isinstance(symbols_raw, list):
        raise ParamsError("'symbols' must be a list")
    if not isinstance(types_h, str):
        raise ParamsError("'types_h' must be a string")
    if not isinstance(references_raw, list):
        raise ParamsError("'references' must be a list")
    warnings: list[str] = []
    symbols = []
    for index, raw in enumerate(symbols_raw):
        where = raw.get("address") if isinstance(raw, dict) else None
        name = raw.get("name") if isinstance(raw, dict) else None
        label = f"{where if isinstance(where, str) else f'symbols[{index}]'} {name or ''}".strip()
        try:
            symbols.append(_parse_symbol(raw, arch, warnings, label))
        except (ValueError, TypeError) as exc:
            warnings.append(f"{label}: {exc}")
    references = []
    for index, raw in enumerate(references_raw):
        label = (
            f"reference {raw.get('from')} -> {raw.get('to')} ({raw.get('kind')})"
            if isinstance(raw, dict)
            else f"references[{index}]"
        )
        try:
            if not isinstance(raw, dict):
                raise ValueError("not an object")
            kind = raw.get("kind")
            if kind not in REFERENCE_KINDS:
                raise ValueError(f"unknown kind {kind!r} (known: {', '.join(REFERENCE_KINDS)})")
            references.append(
                ApplyReference(
                    mapping.to_ghidra_address(raw.get("from"), arch),
                    mapping.to_ghidra_address(raw.get("to"), arch),
                    kind,
                    label,
                )
            )
        except ValueError as exc:
            warnings.append(f"{label}: {exc}")
    return symbols, types_h, references, warnings


# -- C text helpers (pure) -------------------------------------------------------------------------------------

_OWN_CALLING_CONVENTION = re.compile(r"\b__(?:cdecl|stdcall|fastcall|thiscall|pascal|watcall|regcall)\w*\b")


def without_keyword(type_text: str) -> str:
    """'struct foo *' -> 'foo *': Ghidra's DataTypeParser and FunctionSignatureParser do not resolve 'struct foo',
    'foo' they do (the CParser stores structs, unions and enums under their name). 'const' and 'volatile' they do
    not know at all; they are dropped ('const char *' -> 'char *')."""
    type_text = re.sub(r"\b(?:const|volatile)\b\s*", "", type_text)
    return re.sub(r"\b(?:struct|union|enum)\s+(?=\w)", "", type_text)


def signature_for_ghidra(signature: str) -> tuple[str, str | None]:
    """A prototype in the form Ghidra's FunctionSignatureParser understands, and its calling convention apart.
    The parser knows no calling convention ('int __cdecl f(...)' -> return type 'int __cdecl') and splits return
    type and name at the last space ('char *strcpy(...)' -> name '*strcpy')."""
    signature = without_keyword(signature.strip().rstrip(";"))
    head, paren, rest = signature.partition("(")
    convention = None
    if m := _OWN_CALLING_CONVENTION.search(head):
        convention, head = m.group(0), head[: m.start()] + " " + head[m.end() :]
    head = re.sub(r"\*(\w+\s*)$", r"* \1", re.sub(r"\s+", " ", head).strip())
    return head + paren + rest, convention


def clean_c(text: str) -> str:
    """Remove comments, preprocessor lines and the 16-bit keywords far/near/huge."""
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group().count("\n") or " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    text = "\n".join("" if line.lstrip().startswith("#") else line for line in text.splitlines())
    return re.sub(r"\b_{0,2}(far|near|huge)\b", "", text)


def split_declarations(cleaned: str) -> list[str]:
    """Top-level declarations of cleaned C text (split at `;` outside braces), whitespace collapsed."""
    result, depth, start = [], 0, 0
    for index, char in enumerate(cleaned):
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
        elif char == ";" and depth == 0:
            result.append(cleaned[start : index + 1])
            start = index + 1
    if cleaned[start:].strip():
        result.append(cleaned[start:])
    return [d for d in (re.sub(r"\s+", " ", d).strip() for d in result) if d and d != ";"]


_STRUCT = re.compile(r"\bstruct\s+(\w+)\s*\{([^{}]*)\}\s*;")
_OFFSET_COMMENT = re.compile(r"/\*\s*\+0x([0-9a-fA-F]+)\s*\*/")
_GAP_NAME = re.compile(r"\b(?:gap|luecke)_([0-9a-fA-F]+)\s*\[\d+\]\s*;")  # migrated workspaces keep `luecke_`
_FIELD_NAME = re.compile(r"(\w+)\s*(?:\[\s*\d+\s*\])*\s*;")


def struct_offsets(text: str) -> dict[str, list[tuple[str, int]]]:
    """Fields with offset per struct from the comments '/* +0xN */' (gaps 'char gap_N[n];' need no comment).
    Only structs in which every field has an offset; hand-written ones without comments are left out."""
    result: dict[str, list[tuple[str, int]]] = {}
    for m in _STRUCT.finditer(text):
        fields = []
        for line in m.group(2).splitlines():
            bare = _OFFSET_COMMENT.sub("", line)
            if not bare.strip() or not (n := _FIELD_NAME.search(re.sub(r"/\*.*?\*/|//.*", "", bare))):
                continue
            if k := _OFFSET_COMMENT.search(line):
                fields.append((n.group(1), int(k.group(1), 16)))
            elif gap := _GAP_NAME.search(bare):
                fields.append((n.group(1), int(gap.group(1), 16)))
            else:
                break
        else:
            if fields:
                result[m.group(1)] = fields
    return result


def wanted_sets(symbols: dict[GhidraAddress, ApplySymbol], references: list[ApplyReference]) -> dict[str, set[str]]:
    """What the knowledge sets in Ghidra (Ghidra address texts): function comments, PRE comments, signatures,
    references. Kept in `applied.json` so the next apply can take back what is no longer wanted."""
    function, line, signature = set(), set(), set()
    for s in symbols.values():
        if s.kind == "function":
            if s.comment:
                function.add(s.address.text())
            if s.signature:
                signature.add(s.address.text())
            line.update(c.address.text() for c in s.line_comments)
        elif s.comment:
            line.add(s.address.text())
    reference = {f"{r.from_.text()}>{r.to.text()}>{r.kind}" for r in references}
    return {"function": function, "line": line, "signature": signature, "reference": reference}


# -- Ghidra ----------------------------------------------------------------------------------------------------


def _message(exc: Exception) -> str:
    """A Java exception without its class name."""
    text = exc.getMessage() if hasattr(exc, "getMessage") else None
    return str(text or exc).strip()


def _layout(s) -> list[tuple[str, int]]:
    return [(str(c.getFieldName()), int(c.getOffset())) for c in s.getDefinedComponents()]


def _fits(s, wanted: list[tuple[str, int]]) -> bool:
    """Layout as in the offset comments and no padding at the end (naturally aligned, a struct of int + 5 short
    is rounded up to 16 bytes instead of 14)."""
    end = max((c.getOffset() + c.getLength() for c in s.getDefinedComponents()), default=0)
    return _layout(s) == wanted and s.getLength() == end


def _structs_by_offsets(dtm, wanted: dict[str, list[tuple[str, int]]], warnings: list[str]) -> None:
    """The CParser lays structs out naturally aligned; the targets (Watcom) pack them (int at +0x1). The offset
    comments decide: if Ghidra's layout differs, the struct is packed (alignment 1); if it still does not fit, the
    fields are put at their offsets one by one; otherwise a warning."""
    if not wanted:
        return
    structs = {
        str(s.getName()): s
        for s in dtm.getAllStructures()
        if str(s.getName()) in wanted and s.getCategoryPath().isRoot()
    }
    for _ in range(len(structs)):  # an outer struct changes its layout when an inner one is packed
        changed = False
        for name, s in structs.items():
            if not _fits(s, wanted[name]) and not (s.isPackingEnabled() and s.getExplicitPackingValue() == 1):
                s.setPackingEnabled(True)
                s.setExplicitPackingValue(1)
                changed = True
        if not changed:
            break
    for name, s in structs.items():
        if _fits(s, wanted[name]):
            continue
        fields = [
            (c.getDataType(), c.getLength(), str(c.getFieldName()), c.getComment()) for c in s.getDefinedComponents()
        ]
        offsets = dict(wanted[name])
        if [f[2] for f in fields] == [n for n, _ in wanted[name]]:
            try:
                s.setPackingEnabled(False)
                s.deleteAll()
                for data_type, length, field_name, comment in fields:
                    s.insertAtOffset(offsets[field_name], data_type, length, field_name, comment)
            except Exception:
                pass
        if not _fits(s, wanted[name]):
            actual = ", ".join(f"{n} +0x{o:x}" for n, o in _layout(s))
            warnings.append(f"types.h: struct {name} does not match its offset comments (Ghidra: {actual})")


class GhidraApplier:
    """Applies knowledge to an open program. `to_g` maps a `GhidraAddress` to a Ghidra address, `to_spec` back
    (None for non-memory addresses); `folder` holds `applied.json`."""

    def __init__(
        self,
        pyghidra,
        program,
        folder: Path,
        to_g: Callable[[GhidraAddress], Any],
        to_spec: Callable[[Any], GhidraAddress | None],
    ):
        self.pyghidra = pyghidra
        self.p = program
        self.folder = Path(folder)
        self.to_g = to_g
        self.to_spec = to_spec

    def apply(
        self,
        symbols: list[ApplySymbol],
        types_h: str,
        references: list[ApplyReference],
        calling_convention: str | None,
    ) -> tuple[int, list[str]]:
        from ghidra.program.model.symbol import SourceType  # type: ignore[import-not-found]

        pyghidra, p = self.pyghidra, self.p
        warnings: list[str] = []
        applied, new = 0, False
        active: dict[GhidraAddress, ApplySymbol] = {}
        for s in symbols:
            if s.address in active:
                warnings.append(f"{s.label}: duplicate symbol at this address; the last one wins")
            active[s.address] = s
        wanted = wanted_sets(active, references)
        if types_h.strip():
            self._apply_types(types_h, warnings)
        with pyghidra.transaction(p, "apply knowledge"):
            self._clean_up(active, wanted, warnings)
            for s in active.values():
                try:
                    new |= self._apply_symbol(s)
                    applied += 1
                except Exception as exc:
                    warnings.append(f"{s.label}: {_message(exc)}")
            count, created = self._apply_references(references, warnings)
            applied += count
            new |= created
            self._set_calling_convention(active, calling_convention, warnings)
            for f in p.getFunctionManager().getFunctions(True):
                a = self.to_spec(f.getEntryPoint())
                if a is None:
                    continue
                s = active.get(a)
                default = mapping.default_name(a)
                if not (s and s.name) and str(f.getName()) != default:
                    try:
                        f.setName(default, SourceType.ANALYSIS)
                    except Exception as exc:
                        warnings.append(f"{a.text()}: default name not set: {_message(exc)}")
        if new:
            self._reanalyze()
        p.save("knowledge applied", pyghidra.task_monitor())
        write_atomic(
            self.folder / "applied.json",
            (json.dumps({k: sorted(v) for k, v in sorted(wanted.items())}) + "\n").encode("utf-8"),
        )
        return applied, warnings

    # -- types.h ---------------------------------------------------------------------------------------------

    def _apply_types(self, text: str, warnings: list[str]) -> None:
        """Parse the whole text as Decomp did; when that fails, roll back and parse declaration by declaration
        with one parser (it keeps earlier typedefs), a warning per failed declaration."""
        from ghidra.app.util.cparser.C import CParser  # type: ignore[import-not-found]

        p = self.p
        dtm = p.getDataTypeManager()
        cleaned = clean_c(text)
        whole_error = None
        tx = p.startTransaction("types.h")
        try:
            CParser(dtm, True, None).parse(cleaned)
        except Exception as exc:
            whole_error = _message(exc)
        finally:
            p.endTransaction(tx, whole_error is None)  # a failed parse is rolled back
        tx = p.startTransaction("types.h, declarations")
        try:
            if whole_error is not None:
                before = len(warnings)
                parser = CParser(dtm, True, None)
                for declaration in split_declarations(cleaned):
                    try:
                        parser.parse(declaration)
                    except Exception as exc:
                        short = declaration if len(declaration) <= 60 else declaration[:57] + "..."
                        warnings.append(f"types.h: {short}: {_message(exc)}")
                if len(warnings) == before:
                    warnings.append(f"types.h: {whole_error} (applied declaration by declaration)")
            _structs_by_offsets(dtm, struct_offsets(text), warnings)
        finally:
            p.endTransaction(tx, True)

    # -- taking back what is no longer wanted ----------------------------------------------------------------

    def _load_applied(self, warnings: list[str]) -> dict:
        path = self.folder / "applied.json"
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or not all(isinstance(v, list) for v in data.values()):
                raise ValueError("not an object of lists")
            return data
        except (OSError, ValueError) as exc:
            warnings.append(f"{path.name} unreadable, treated as empty: {exc}")
            return {}

    def _clean_up(self, active: dict[GhidraAddress, ApplySymbol], wanted: dict[str, set[str]], warnings) -> None:
        """Take back what earlier knowledge set and no active entry carries any more."""
        from ghidra.program.model.symbol import SourceType, SymbolType  # type: ignore[import-not-found]

        p = self.p
        fm, st = p.getFunctionManager(), p.getSymbolTable()
        for sym in list(st.getAllSymbols(True)):
            if sym.getSource() != SourceType.USER_DEFINED or sym.getSymbolType() != SymbolType.LABEL:
                continue
            a = self.to_spec(sym.getAddress()) if sym.getAddress().isMemoryAddress() else None
            s = active.get(a) if a else None
            if s and s.kind != "function" and s.name == str(sym.getName()):
                continue
            try:
                sym.delete()
            except Exception as exc:
                where = a.text() if a else str(sym.getAddress())
                warnings.append(f"{where}: label {sym.getName()} not removed: {_message(exc)}")
        earlier = self._load_applied(warnings)
        for text in earlier.get("signature", []):
            try:
                if text in wanted["signature"]:
                    continue
                a = GhidraAddress.parse(text)
                s = active.get(a)
                if s and any(local.place.startswith("param:") for local in s.locals):
                    wanted["signature"].add(text)  # parameters stay for the locals; checked again next time
                    continue
                f = fm.getFunctionAt(self.to_g(a))
                if f is not None and f.getSignatureSource() == SourceType.USER_DEFINED:
                    self._reset_signature(f)
            except Exception as exc:
                warnings.append(f"{text}: signature not reset: {_message(exc)}")
        for kind in ("function", "line"):
            for text in earlier.get(kind, []):
                try:
                    if text in wanted[kind]:
                        continue
                    g = self.to_g(GhidraAddress.parse(text))
                    if kind == "function":
                        if (f := fm.getFunctionAt(g)) is not None:
                            f.setComment(None)
                    else:
                        self._comment(g, None)
                except Exception as exc:
                    warnings.append(f"{text}: comment not removed: {_message(exc)}")
        rm = p.getReferenceManager()
        for text in earlier.get("reference", []):
            if text in wanted["reference"]:
                continue
            try:
                source, target, _kind = text.split(">")
                g_from, g_to = self.to_g(GhidraAddress.parse(source)), self.to_g(GhidraAddress.parse(target))
                for ref in list(rm.getReferencesFrom(g_from)):
                    if ref.getToAddress().equals(g_to) and ref.getSource() == SourceType.USER_DEFINED:
                        rm.delete(ref)
            except Exception as exc:
                warnings.append(f"reference {text}: not removed: {_message(exc)}")

    @staticmethod
    def _reset_signature(f) -> None:
        """Leave parameters and return type to Ghidra again (source DEFAULT, dynamic storage)."""
        from ghidra.program.model.data import DataType  # type: ignore[import-not-found]
        from ghidra.program.model.listing import Function  # type: ignore[import-not-found]
        from ghidra.program.model.symbol import SourceType  # type: ignore[import-not-found]
        from java.util import ArrayList  # type: ignore[import-not-found]

        f.updateFunction(
            None, None, ArrayList(), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True, SourceType.DEFAULT
        )
        f.setReturnType(DataType.DEFAULT, SourceType.DEFAULT)
        f.setSignatureSource(SourceType.DEFAULT)

    # -- single items ----------------------------------------------------------------------------------------

    def _comment(self, g, text: str | None) -> None:
        listing = self.p.getListing()
        try:
            from ghidra.program.model.listing import CommentType  # type: ignore[import-not-found]

            listing.setComment(g, CommentType.PRE, text)
        except ImportError:
            from ghidra.program.model.listing import CodeUnit  # type: ignore[import-not-found]

            listing.setComment(g, CodeUnit.PRE_COMMENT, text)

    def _type(self, name: str):
        from ghidra.util.data import DataTypeParser  # type: ignore[import-not-found]

        dtm = self.p.getDataTypeManager()
        return DataTypeParser(dtm, dtm, None, DataTypeParser.AllowedDataTypes.ALL).parse(without_keyword(name))

    def _apply_references(self, references: list[ApplyReference], warnings: list[str]) -> tuple[int, bool]:
        """Observed targets of indirect calls/jumps as computed references (USER_DEFINED)."""
        from ghidra.program.flatapi import FlatProgramAPI  # type: ignore[import-not-found]
        from ghidra.program.model.symbol import RefType, SourceType  # type: ignore[import-not-found]

        p, applied, new = self.p, 0, False
        rm, listing, flat = p.getReferenceManager(), p.getListing(), FlatProgramAPI(p)
        for r in references:
            try:
                source, target = self.to_g(r.from_), self.to_g(r.to)
                for g in (source, target):
                    if listing.getInstructionAt(g) is None:
                        flat.disassemble(g)
                        new = True
                if not any(ref.getToAddress().equals(target) for ref in rm.getReferencesFrom(source)):
                    ref_type = RefType.COMPUTED_CALL if r.kind == "call" else RefType.COMPUTED_JUMP
                    rm.addMemoryReference(source, target, ref_type, SourceType.USER_DEFINED, 0)
                applied += 1
            except Exception as exc:
                warnings.append(f"{r.label}: {_message(exc)}")
        return applied, new

    def _apply_symbol(self, s: ApplySymbol) -> bool:
        from ghidra.app.cmd.function import ApplyFunctionSignatureCmd  # type: ignore[import-not-found]
        from ghidra.app.util.parser import FunctionSignatureParser  # type: ignore[import-not-found]
        from ghidra.program.flatapi import FlatProgramAPI  # type: ignore[import-not-found]
        from ghidra.program.model.data import DataUtilities  # type: ignore[import-not-found]
        from ghidra.program.model.symbol import SourceType  # type: ignore[import-not-found]

        p, g, new = self.p, self.to_g(s.address), False
        fm, st = p.getFunctionManager(), p.getSymbolTable()
        if s.kind == "function":
            f = fm.getFunctionAt(g)
            if f is None:
                flat = FlatProgramAPI(p)
                flat.disassemble(g)
                f = flat.createFunction(g, None)
                if f is None:
                    raise RuntimeError("function could not be created")
                new = True
            self._shorten_enclosing(f)
            if s.name:  # before the signature: a prototype Ghidra rejects costs only the prototype
                f.setName(s.name, SourceType.USER_DEFINED)
            if s.signature:
                text, convention = signature_for_ghidra(s.signature)
                signature = FunctionSignatureParser(p.getDataTypeManager(), None).parse(f.getSignature(), text)
                if convention:
                    signature.setCallingConvention(convention)
                ApplyFunctionSignatureCmd(g, signature, SourceType.USER_DEFINED).applyTo(p)
                if convention and f.getCallingConventionName() != convention:
                    f.setCallingConvention(convention)
            if s.comment:
                f.setComment(s.comment)
            for c in s.line_comments:
                self._comment(self.to_g(c.address), c.text)
            for local in s.locals:
                self._local(f, local)
        else:
            if s.name:
                # an own label instead of a rename: once refuted, Ghidra's label counts again
                st.createLabel(g, s.name, SourceType.USER_DEFINED).setPrimary()
            if s.kind == "global" and s.data_type:
                DataUtilities.createData(
                    p, g, self._type(s.data_type), -1, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA
                )
            if s.comment:
                self._comment(g, s.comment)
        return new

    def _shorten_enclosing(self, f) -> None:
        """A function in the middle of another's body (Watcom drops a tail call into the directly following
        function, the previous one runs into it): Ghidra lets both bodies overlap, but the previous one ends
        before."""
        fm, start = self.p.getFunctionManager(), f.getEntryPoint()
        for other in list(fm.getFunctionsOverlapping(f.getBody())):
            if other.getEntryPoint().compareTo(start) < 0 and other.getBody().contains(start):
                other.setBody(other.getBody().subtract(f.getBody()))

    def _local(self, f, local: ApplyLocal) -> None:
        from ghidra.program.model.symbol import SourceType  # type: ignore[import-not-found]

        if local.place.startswith("param:"):
            parameter = f.getParameter(int(local.place[6:]) - 1)
            if parameter is None:
                raise RuntimeError(f"parameter {local.place} does not exist")
            parameter.setName(local.name, SourceType.USER_DEFINED)
            if local.data_type:
                parameter.setDataType(self._type(local.data_type), SourceType.USER_DEFINED)
        elif local.place.startswith("stack:"):
            offset = int(local.place[6:], 16)
            for v in f.getLocalVariables():
                if v.isStackVariable() and v.getStackOffset() == offset:
                    v.setName(local.name, SourceType.USER_DEFINED)
                    if local.data_type:
                        v.setDataType(self._type(local.data_type), SourceType.USER_DEFINED)
                    return
            raise RuntimeError(f"no stack variable at {local.place}")
        else:
            raise RuntimeError(f"local {local.name}: places other than param: and stack: are not applied yet")

    def _set_calling_convention(self, active, name: str | None, warnings: list[str]) -> None:
        """Default calling convention for every function whose knowledge signature names none of its own."""
        if not name:
            return
        for f in self.p.getFunctionManager().getFunctions(True):
            a = self.to_spec(f.getEntryPoint())
            s = active.get(a) if a else None
            if s and s.signature and _OWN_CALLING_CONVENTION.search(s.signature):
                continue
            if f.getCallingConventionName() != name:
                try:
                    f.setCallingConvention(name)
                except Exception as exc:
                    warnings.append(f"{a.text() if a else f.getEntryPoint()}: calling convention {name} not set: "
                                    f"{_message(exc)}")

    def _reanalyze(self) -> None:
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager  # type: ignore[import-not-found]

        with self.pyghidra.transaction(self.p, "reanalysis"):
            AutoAnalysisManager.getAnalysisManager(self.p).startAnalysis(self.pyghidra.task_monitor())
