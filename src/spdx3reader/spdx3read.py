# SPDX-FileCopyrightText: 2025-present Arthit Suriyawongkul <suriyawa@tcd.ie>
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

import json

from spdx_python_model import v3_0_1 as spdx_3

def read_json_file(filepath: str):
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Read and print an SPDX 3 JSON file.")
    parser.add_argument("filepath", help="Path to the SPDX 3 JSON file")
    args = parser.parse_args()

    data = read_json_file(args.filepath)
    print(json.dumps(data, indent=2))

if __name__ == "__main__":
    main()
