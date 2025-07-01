# SPDX-FileCopyrightText: 2025-present Arthit Suriyawongkul <suriyawa@tcd.ie>
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

import json

from spdx_python_model import v3_0_1 as spdx3

def read_json_file(filepath: str):
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def deserialize_spdx_json_file(filepath: str) -> spdx3.SHACLObjectSet:
    object_set = spdx3.SHACLObjectSet()
    with open(filepath, 'r', encoding='utf-8') as f:
        spdx3.JSONLDDeserializer().read(f, object_set)
        return object_set

# def json_to_spdx_graph(json_data) -> list[spdx3.SHACLObject]:
#     """
#     Convert JSON data to an SPDX 3.0.1 document.
#     """
#     spdx3_classes = {
#         name: cls
#         for name, cls in vars(spdx3).items()
#         if inspect.isclass(cls) and cls.__module__ == spdx3.__name__
#     }

#     json_graph_data = json_data.get("@graph", [])
#     for entry in json_graph_data:
#         type_name = entry.get("type")
#         if not type_name:
#             continue
#         cls = spdx3_classes.get(type_name)
#         if cls is None:
#             continue  # Unknown type, skip
#         obj = cls()
#         for k, v in entry.items():
#             if k != "type":
#                 obj[k] = v
#         graph.append(obj)

#     return graph

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Read and print an SPDX 3 JSON file.")
    parser.add_argument("filepath", help="Path to the SPDX 3 JSON file")
    parser.add_argument("-D", "--dump", action="store_true", help="Print the JSON content")
    parser.add_argument("-T", "--tree", action="store_true", help="Print the SPDX object tree")
    args = parser.parse_args()

    if args.dump:
        json_data = read_json_file(args.filepath)
        print(json.dumps(json_data, indent=2))
    
    spdx_object_set = deserialize_spdx_json_file(args.filepath)
    if args.tree:
        print("SPDX Object Tree:")
        spdx3.print_tree(spdx_object_set.objects)
        print(len(spdx_object_set.objects), "SPDX objects found in the JSON file.")

if __name__ == "__main__":
    main()
