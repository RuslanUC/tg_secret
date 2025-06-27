#  Pyrogram - Telegram MTProto API Client Library for Python
#  Copyright (C) 2017-present Dan <https://github.com/delivrance>
#
#  This file is part of Pyrogram.
#
#  Pyrogram is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  Pyrogram is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with Pyrogram.  If not, see <http://www.gnu.org/licenses/>.

import re
import shutil
from collections import defaultdict
from functools import partial
from pathlib import Path


HOME_PATH = Path("compiler/secret_api")
DESTINATION_PATH = Path("tg_secret/raw")
NOTICE_PATH = "NOTICE"

SECTION_RE = re.compile(r"---(\w+)---")
LAYER_RE = re.compile(r"===(\d+)===")
COMBINATOR_RE = re.compile(r"^([\w.]+)#([0-9a-f]+)\s(?:.*)=\s([\w<>.]+);$", re.MULTILINE)
ARGS_RE = re.compile(r"[^{](\w+):([\w?!.<>#]+)")
FLAGS_RE = re.compile(r"flags(\d?)\.(\d+)\?")
FLAGS_RE_2 = re.compile(r"flags(\d?)\.(\d+)\?([\w<>.]+)")
FLAGS_RE_3 = re.compile(r"flags(\d?):#")
INT_RE = re.compile(r"int(\d+)")

CORE_TYPES = ["int", "long", "int128", "int256", "double", "bytes", "string", "Bool", "true"]

WARNING = """
# # # # # # # # # # # # # # # # # # # # # # # #
#               !!! WARNING !!!               #
#          This is a generated file!          #
# All changes made in this file will be lost! #
# # # # # # # # # # # # # # # # # # # # # # # #
""".strip()

# noinspection PyShadowingBuiltins
open = partial(open, encoding="utf-8")

types_to_constructors = {}
types_to_functions = {}
constructors_to_functions = {}
namespaces_to_types = {}
namespaces_to_constructors: defaultdict[str, list[str]] = defaultdict(list)
namespaces_to_classes: defaultdict[str, list[str]] = defaultdict(list)


class Combinator:
    def __init__(
            self, qualname: str, namespace: str, name: str, id: str, has_flags: bool,
            args: list[tuple[str, str]], qualtype: str, typespace: str, type: str, layer: int,
    ) -> None:
        self.qualname = qualname
        self.namespace = namespace
        self.name = name
        self.id = id
        self.has_flags = has_flags
        self.args = args
        self.qualtype = qualtype
        self.typespace = typespace
        self.type = type
        self.layer = layer


def snake(s: str):
    # https://stackoverflow.com/q/1175208
    s = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", s)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s).lower()


def camel(s: str):
    return "".join([i[0].upper() + i[1:] for i in s.split("_")])


# noinspection PyShadowingBuiltins, PyShadowingNames
def get_type_hint(type: str) -> str:
    is_flag = FLAGS_RE.match(type)
    is_core = False

    if is_flag:
        type = type.split("?")[1]

    if type in CORE_TYPES:
        is_core = True

        if type == "long" or "int" in type:
            type = "int"
        elif type == "double":
            type = "float"
        elif type == "string":
            type = "str"
        elif type in ["Bool", "true"]:
            type = "bool"
        else:  # bytes and object
            type = "bytes"

    if type in ["Object", "!X"]:
        return "SecretTLObject"

    if re.match("^vector", type, re.I):
        is_core = True

        sub_type = type.split("<")[1][:-1]
        type = f"list[{get_type_hint(sub_type)}]"

    if is_core:
        return f"{type} | None = None" if is_flag else type
    else:
        ns, name = type.split(".") if "." in type else ("", type)
        type = f'raw.base.' + ".".join([ns, name]).strip(".") + ''

        return f'{type}{" = None" if is_flag else ""}'


def sort_args(args):
    """Put flags at the end"""
    args = args.copy()
    flags = [i for i in args if FLAGS_RE.match(i[1])]

    for i in flags:
        args.remove(i)

    for i in args[:]:
        if re.match(r"flags\d?", i[0]) and i[1] == "#":
            args.remove(i)

    return args + flags


# noinspection PyShadowingBuiltins
def start():
    shutil.rmtree(DESTINATION_PATH / "types", ignore_errors=True)
    shutil.rmtree(DESTINATION_PATH / "base", ignore_errors=True)

    with open(HOME_PATH / "source/end_to_end.tl") as secret:
        schema = secret.read().splitlines()

    with open(HOME_PATH / "template/combinator.txt") as f2:
        combinator_tmpl = f2.read()

    current_layer = None
    max_layer = None
    combinators = []

    combinator_by_name: defaultdict[str, list[Combinator]] = defaultdict(list)

    for line in schema:
        # Save the layer version
        layer_match = LAYER_RE.match(line)
        if layer_match:
            current_layer = int(layer_match.group(1))
            max_layer = max(max_layer or 0, current_layer)
            continue

        combinator_match = COMBINATOR_RE.match(line)
        if combinator_match:
            # noinspection PyShadowingBuiltins
            qualname, id, qualtype = combinator_match.groups()

            namespace, name = qualname.split(".") if "." in qualname else ("", qualname)
            name = camel(name)
            qualname = ".".join([namespace, name]).lstrip(".")

            typespace, type = qualtype.split(".") if "." in qualtype else ("", qualtype)
            type = camel(type)
            qualtype = ".".join([typespace, type]).lstrip(".")

            # Pingu!
            has_flags = not not FLAGS_RE_3.findall(line)

            args = ARGS_RE.findall(line)

            # Fix arg name being "self" (reserved python keyword)
            for i, item in enumerate(args):
                if item[0] == "self":
                    args[i] = ("is_self", item[1])

            combinator = Combinator(
                qualname=qualname,
                namespace=namespace,
                name=name,
                id=f"0x{id}",
                has_flags=has_flags,
                args=args,
                qualtype=qualtype,
                typespace=typespace,
                type=type,
                layer=current_layer,
            )

            combinators.append(combinator)
            combinator_by_name[qualname].append(combinator)

    for dup_combinators in combinator_by_name.values():
        if len(dup_combinators) <= 1:
            continue
        for combinator in dup_combinators:
            combinator.name += f"_{combinator.layer}"
            combinator.qualname += f"_{combinator.layer}"

    for c in combinators:
        qualtype = c.qualtype

        if qualtype.startswith("Vector"):
            qualtype = qualtype.split("<")[1][:-1]

        d = types_to_constructors

        if qualtype not in d:
            d[qualtype] = []

        d[qualtype].append(c.qualname)

        key = c.namespace

        if key not in namespaces_to_types:
            namespaces_to_types[key] = []

        if c.type not in namespaces_to_types[key]:
            namespaces_to_types[key].append(c.type)

    for k, v in types_to_constructors.items():
        for i in v:
            try:
                constructors_to_functions[i] = types_to_functions[k]
            except KeyError:
                pass

    for c in combinators:
        sorted_args = sort_args(c.args)

        arguments = (
            (", *, " if c.args else "") +
            (", ".join(
                [f"{i[0]}: {get_type_hint(i[1])}"
                 for i in sorted_args]
            ) if sorted_args else "")
        )

        fields = "\n        ".join(
            [f"self.{i[0]} = {i[0]}  # {i[1]}"
             for i in sorted_args]
        ) if sorted_args else "pass"

        docstring = ""
        docstring += "Telegram API type.\n"
        docstring += f"\n    Details:\n        - Layer: ``{c.layer}``\n        - ID: ``{c.id[2:].upper()}``\n"

        write_types = read_types = "" if c.has_flags else "# No flags\n        "

        for arg_name, arg_type in c.args:
            flag = FLAGS_RE_2.match(arg_type)

            if re.match(r"flags\d?", arg_name) and arg_type == "#":
                write_flags = []

                for i in c.args:
                    flag = FLAGS_RE_2.match(i[1])

                    if flag:
                        if arg_name != f"flags{flag.group(1)}":
                            continue

                        if flag.group(3) == "true" or flag.group(3).startswith("Vector"):
                            write_flags.append(f"{arg_name} |= (1 << {flag.group(2)}) if self.{i[0]} else 0")
                        else:
                            write_flags.append(
                                f"{arg_name} |= (1 << {flag.group(2)}) if self.{i[0]} is not None else 0")

                write_flags = "\n        ".join([
                    f"{arg_name} = 0",
                    "\n        ".join(write_flags),
                    f"b.write(write_int({arg_name}))\n        "
                ])

                write_types += write_flags
                read_types += f"\n        {arg_name} = read_int(b)\n        "

                continue

            if flag:
                number, index, flag_type = flag.groups()

                if flag_type == "true":
                    read_types += "\n        "
                    read_types += f"{arg_name} = True if flags{number} & (1 << {index}) else False"
                elif flag_type in CORE_TYPES:
                    write_types += "\n        "
                    write_types += f"if self.{arg_name} is not None:\n            "
                    write_types += f"b.write(write_{flag_type.lower()}(self.{arg_name}))\n        "

                    read_types += "\n        "
                    read_types += f"{arg_name} = read_{flag_type.lower()}(b) if flags{number} & (1 << {index}) else None"
                elif "vector" in flag_type.lower():
                    sub_type = arg_type.split("<")[1][:-1]

                    write_types += "\n        "
                    write_types += f"if self.{arg_name} is not None:\n            "
                    write_types += "b.write(Vector.write_{}(self.{}{}))\n        ".format(
                        "primitive_list" if sub_type in CORE_TYPES else "list",
                        arg_name, f", write_{sub_type.lower()}" if sub_type in CORE_TYPES else ""
                    )

                    read_types += "\n        "
                    read_types += "{} = SecretTLObject.read(b{}) if flags{} & (1 << {}) else []\n        ".format(
                        arg_name, f", read_{sub_type.lower()}" if sub_type in CORE_TYPES else ", SecretTLObject.read", number, index
                    )
                else:
                    write_types += "\n        "
                    write_types += f"if self.{arg_name} is not None:\n            "
                    write_types += f"b.write(self.{arg_name}.write())\n        "

                    read_types += "\n        "
                    read_types += f"{arg_name} = SecretTLObject.read(b) if flags{number} & (1 << {index}) else None\n        "
            else:
                if arg_type in CORE_TYPES:
                    write_types += "\n        "
                    write_types += f"b.write(write_{arg_type.lower()}(self.{arg_name}))\n        "

                    read_types += "\n        "
                    read_types += f"{arg_name} = read_{arg_type.lower()}(b)\n        "
                elif "vector" in arg_type.lower():
                    sub_type = arg_type.split("<")[1][:-1]

                    write_types += "\n        "
                    write_types += "b.write(Vector.write_{}(self.{}{}))\n        ".format(
                        "primitive_list" if sub_type in CORE_TYPES else "list",
                        arg_name, f", write_{sub_type.lower()}" if sub_type in CORE_TYPES else ""
                    )

                    read_types += "\n        "
                    read_types += "{} = Vector.read(b{})\n        ".format(
                        arg_name, f", read_{sub_type.lower()}" if sub_type in CORE_TYPES else ", SecretTLObject.read"
                    )
                else:
                    write_types += "\n        "
                    write_types += f"b.write(self.{arg_name}.write())\n        "

                    read_types += "\n        "
                    read_types += f"{arg_name} = SecretTLObject.read(b)\n        "

        slots = ", ".join([f'"{i[0]}"' for i in sorted_args])
        return_arguments = ", ".join([f"{i[0]}={i[0]}" for i in sorted_args])

        namespaces_to_constructors[c.namespace].append(c.name)
        namespaces_to_classes[c.namespace].append(combinator_tmpl.format(
            warning=WARNING,
            name=c.name,
            docstring=docstring,
            slots=f"{slots}," if slots else "",
            id=c.id,
            qualname=f"types.{c.qualname}",
            arguments=arguments,
            fields=fields,
            read_types=read_types,
            write_types=write_types,
            return_arguments=return_arguments
        ))

    for namespace, types in namespaces_to_types.items():
        base_dir = DESTINATION_PATH / "base" / namespace
        base_dir.mkdir(parents=True, exist_ok=True)
        with open(base_dir / "__init__.py", "w") as f:
            f.write(f"from tg_secret import raw\n\n")
            f.write(f"{WARNING}\n\n")

            for t in types:
                qualtype = f"{namespace}.{t}" if namespace else t
                constructors = sorted(types_to_constructors[qualtype])

                types_pipe = " | ".join([f"raw.types.{c}" for c in constructors])
                f.write(f"{t} = {types_pipe}\n")

                # For isinstance() check
                types_comma = ", ".join([f"raw.types.{c}" for c in constructors])
                f.write(f"{t}Inst = ({types_comma},)\n")

                f.write("\n")

    for namespace, types in namespaces_to_constructors.items():
        base_dir = DESTINATION_PATH / "types" / namespace
        base_dir.mkdir(parents=True, exist_ok=True)
        with open(base_dir / "__init__.py", "w") as f:
            f.write("from __future__ import annotations\n")
            f.write("\n")
            f.write("from io import BytesIO\n")
            f.write("\n")
            f.write("from tg_secret.raw.tl_object import SecretTLObject\n")
            f.write("from tg_secret.raw.vector import Vector\n")
            f.write("from tg_secret.raw.primitives import read_int, read_long, read_double, read_bytes, read_string\n")
            f.write("from tg_secret.raw.primitives import write_int, write_long, write_double, write_bytes, write_string\n")
            f.write("from tg_secret import raw\n")
            f.write("\n")
            f.write(f"{WARNING}\n\n")

            for combinator_class in namespaces_to_classes[namespace]:
                f.write(combinator_class)
                f.write("\n\n")

    with open(DESTINATION_PATH / "all.py", "w", encoding="utf-8") as f:
        f.write("from io import BytesIO\n")
        f.write("import tg_secret.raw\n\n")

        f.write(WARNING + "\n\n")

        f.write(f"layer = {max_layer}\n\n")

        f.write("objects = {\n")

        for c in combinators:
            f.write(f"    {c.id}: tg_secret.raw.types.{c.qualname},\n")

        f.write("    0xbc799737: tg_secret.raw.primitives.BoolFalse,\n")
        f.write("    0x997275b5: tg_secret.raw.primitives.BoolTrue,\n")
        f.write("    0x1cb5c415: tg_secret.raw.vector.Vector,\n")

        f.write("}\n")


if "__main__" == __name__:
    HOME_PATH = Path(".")
    DESTINATION_PATH = Path("../../tg_secret/raw")
    NOTICE_PATH = Path("../../NOTICE")

    start()
