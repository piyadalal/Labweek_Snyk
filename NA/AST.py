from tree_sitter import Parser, Language
import tree_sitter_cpp

parser = Parser()

cpp_lang = Language(tree_sitter_cpp.language())
parser.language = cpp_lang

code = b"""
PyGreenlet* o =
    (PyGreenlet*)PyBaseObject_Type.tp_new(type, mod_globs->empty_tuple, mod_globs->empty_dict);
"""

tree = parser.parse(code)

print("Root:", tree.root_node)


def walk_tree(node, code_bytes):
    if node.type in ["identifier", "type_identifier", "field_identifier"]:
        identifier = code_bytes[node.start_byte:node.end_byte].decode()
        print("Identifier:", identifier)

    for child in node.children:
        walk_tree(child, code_bytes)

code_bytes = code
walk_tree(tree.root_node, code_bytes)


def collect_identifiers(node, code_bytes, identifiers):
    if node.type in ["identifier", "type_identifier"]:
        name = code_bytes[node.start_byte:node.end_byte].decode()
        identifiers.add(name)

    for child in node.children:
        collect_identifiers(child, code_bytes, identifiers)


identifiers = set()
collect_identifiers(tree.root_node, code, identifiers)

print("Collected:", identifiers)


mapping = {}
counter = 1

for name in identifiers:
    mapping[name] = f"VAR_{counter}"
    counter += 1


def anonymize(code, tree):
    code_bytes = code
    replacements = []

    def collect(node):
        if node.type in ["identifier", "type_identifier"]:
            name = code_bytes[node.start_byte:node.end_byte].decode()
            replacements.append((node.start_byte, node.end_byte, name))

        for child in node.children:
            collect(child)

    collect(tree.root_node)

    mapping = {}
    counter = 1

    for _, _, name in replacements:
        if name not in mapping:
            mapping[name] = f"VAR_{counter}"
            counter += 1

    code_str = code.decode()

    for start, end, name in reversed(replacements):
        code_str = (
            code_str[:start]
            + mapping[name]
            + code_str[end:]
        )

    return code_str

anonymized_code = anonymize(code, tree)
print(anonymized_code)