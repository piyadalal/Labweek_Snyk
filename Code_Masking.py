import ast
from tree_sitter import Parser, Language
import tree_sitter_cpp
import tree_sitter_php
import tree_sitter_python
import re
import ast
import builtins


print(dir(tree_sitter_php))

# -----------------------------
# Setup Tree-Sitter Parsers
# -----------------------------


php_parser = Parser()

php_lang = Language(tree_sitter_php.language_php())
php_parser.language = php_lang

parser = Parser()

cpp_lang = Language(tree_sitter_cpp.language())
parser.language = cpp_lang


python_parser = Parser()
python_parser.language = Language(tree_sitter_python.language())


# -----------------------------
# Python Anonymizer
# -----------------------------
def anonymize_python(code: str):
    if isinstance(code, str):
        code_bytes = code.encode("utf8")
    else:
        code_bytes = code

    tree = python_parser.parse(code_bytes)

    replacements = []

    def walk(node):
        # Only rename identifiers
        if node.type == "identifier":
            name = code_bytes[node.start_byte:node.end_byte].decode()
            replacements.append((node.start_byte, node.end_byte, name))

        for child in node.children:
            walk(child)

    walk(tree.root_node)

    mapping = {}
    counter = 1

    for _, _, name in replacements:
        if name not in mapping:
            mapping[name] = f"VAR_{counter}"
            counter += 1

    reverse_mapping = {v: k for k, v in mapping.items()}

    code_str = code_bytes.decode()

    # Replace from end to start
    for start, end, name in reversed(replacements):
        code_str = (
            code_str[:start]
            + mapping[name]
            + code_str[end:]
        )

    return code_str, reverse_mapping


def deanonymize_python(code: str, mapping: dict):
    for anon, original in mapping.items():
        code = re.sub(rf"\b{re.escape(anon)}\b", original, code)
    return code


# -----------------------------
# C++ Anonymizer
# -----------------------------





def walk_tree(node, code_bytes):
    if node.type in ["identifier", "type_identifier", "field_identifier"]:
        identifier = code_bytes[node.start_byte:node.end_byte].decode()
        print("Identifier:", identifier)

    for child in node.children:
        walk_tree(child, code_bytes)





def collect_identifiers(node, code_bytes, identifiers):
    if node.type in ["identifier", "type_identifier"]:
        name = code_bytes[node.start_byte:node.end_byte].decode()
        identifiers.add(name)

    for child in node.children:
        collect_identifiers(child, code_bytes, identifiers)





def anonymize_cpp(code_bytes):
    tree = parser.parse(code_bytes)

    replacements = []

    def walk(node):
        if node.type in ["identifier", "type_identifier"]:
            name = code_bytes[node.start_byte:node.end_byte].decode()
            replacements.append((node.start_byte, node.end_byte, name))
        for child in node.children:
            walk(child)

    walk(tree.root_node)

    mapping = {}
    counter = 1

    # IMPORTANT: build mapping from replacements list (ordered)
    for _, _, name in replacements:
        if name not in mapping:
            mapping[name] = f"VAR_{counter}"
            counter += 1

    reverse_mapping = {v: k for k, v in mapping.items()}

    code_str = code_bytes.decode()

    for start, end, name in reversed(replacements):
        code_str = code_str[:start] + mapping[name] + code_str[end:]

    return code_str, reverse_mapping


def deanonymize_cpp(code: str, mapping: dict):
    # replace longer keys first to avoid partial collisions
    for anon in sorted(mapping.keys(), key=len, reverse=True):
        code = code.replace(anon, mapping[anon])
    return code



# -----------------------------
# PHP Anonymizer
# -----------------------------

def prepare_php(code: str) -> bytes:
    wrapped = f"<?php\n{code}\n?>"
    return wrapped.encode("utf8")

def anonymize_php(code: str):
    php_bytes = prepare_php(code)
    tree = php_parser.parse(php_bytes)

    replacements = []

    def collect(node):
        if node.type == "variable_name":
            name = php_bytes[node.start_byte:node.end_byte].decode()
            replacements.append((node.start_byte, node.end_byte, name))
        for child in node.children:
            collect(child)

    collect(tree.root_node)

    mapping = {}
    counter = 1

    for _, _, name in replacements:
        if name not in mapping:
            mapping[name] = f"$VAR_{counter}"
            counter += 1

    reverse_mapping = {v: k for k, v in mapping.items()}

    code_str = php_bytes.decode()

    for start, end, name in reversed(replacements):
        code_str = code_str[:start] + mapping[name] + code_str[end:]

    code_str = code_str.replace("<?php\n", "").replace("\n?>", "")

    return {
        "anonymized_code": code_str,
        "mapping": reverse_mapping
    }
def anonymize_php_(code: str) -> str:
    php_bytes = prepare_php(code)
    tree = php_parser.parse(php_bytes)

    replacements = []

    def collect(node):
        if node.type == "variable_name":
            name = php_bytes[node.start_byte:node.end_byte].decode()
            replacements.append((node.start_byte, node.end_byte, name))
        for child in node.children:
            collect(child)

    collect(tree.root_node)

    mapping = {}
    counter = 1

    for _, _, name in replacements:
        if name not in mapping:
            mapping[name] = f"$VAR_{counter}"
            counter += 1

    code_str = php_bytes.decode()

    for start, end, name in reversed(replacements):
        code_str = code_str[:start] + mapping[name] + code_str[end:]

    # Remove wrapper
    code_str = code_str.replace("<?php\n", "").replace("\n?>", "")

    return code_str


def deanonymize_php(code: str, mapping: dict):
    for var_name, original_name in mapping.items():
        code = code.replace(var_name, original_name)
    return code







def anonymize_by_language(code: str, rule_id: str) -> str:
    language = rule_id.split("/")[0]

    if language == "python":
        code_anonymized, mapping = anonymize_python(code)
        restored = deanonymize_python(code_anonymized, mapping)
        return code_anonymized, restored

    elif language == "cpp":
        code_anonymized, mapping = anonymize_cpp(code)
        restored = deanonymize_cpp(code_anonymized, mapping)
        return code_anonymized, restored

    elif language == "php":
        result = anonymize_php(code)
        anonymized = result["anonymized_code"]
        mapping = result["mapping"]
        restored = deanonymize_php(anonymized, mapping)

        return anonymized, restored

    else:
        return code


snippet_= """  $target_file = $uploadDir . $bn;
    $target_file = str_replace(" ", "_", $target_file);
    if (!isset($_POST['overwrite'])) {
        if (file_exists($target_file)) {
            errorMessage("$target_file already exists");"""

snippet_ = """
        )

        with open(file, "rb") as f:
            with tarfile.open(fileobj=f, mode="r:gz") as tarball:
                tarball.extractall(path=self.jenkins_home)"""
snippet = b"""
PyGreenlet* o =
    (PyGreenlet*)PyBaseObject_Type.tp_new(type, mod_globs->empty_tuple, mod_globs->empty_dict);
"""

anonymized_snippet, restored_snippet = anonymize_by_language(
    snippet,
    "cpp"
)


print("\n--- ANONYMIZED ---\n")
print(anonymized_snippet)
print("\n--- DE-ANONYMIZED ---\n")
print(restored_snippet)


