"""Inventory parser tests: npm's pretty-printed multi-line JSON must
parse (a per-line parse silently collects zero packages), and garbage
input must yield nothing instead of raising.
Run: python3 tests/test_inventory.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aishield import inventory

NPM_PRETTY = """{
  "name": "lib",
  "dependencies": {
    "@scope/tool": {
      "version": "1.2.3",
      "overridden": false
    },
    "plain": {
      "version": "0.0.4"
    },
    "noversion": {}
  }
}"""


def main():
    assert inventory.parse_brew_line("brotli 1.2.1") == ("brotli", "1.2.1")
    assert inventory.parse_brew_line("brotli 1.2.0 1.2.1") == \
        ("brotli", "1.2.1")
    assert inventory.parse_brew_line("c-ares 1.34.8 1.34.6 1.34.9") == \
        ("c-ares", "1.34.9")
    assert inventory.parse_brew_line("lonely") is None
    assert inventory.parse_brew_line("") is None

    items = []
    inventory._parse_npm_json(NPM_PRETTY, items, "local")
    assert len(items) == 3, items
    by_name = {i["name"]: i for i in items}
    assert by_name["@scope/tool"]["version"] == "1.2.3"
    assert by_name["plain"]["version"] == "0.0.4"
    assert by_name["noversion"]["version"] == ""
    assert all(i["ecosystem"] == "npm" and i["manager"] == "npm"
               and i["target"] == "local" for i in items), items

    # garbage / empty / wrong-shape input: nothing, no raise
    for bad in ("", "not json\nmore", "[1, 2]", "null",
                '{"dependencies": null}'):
        items = []
        inventory._parse_npm_json(bad, items, "local")
        assert items == [], bad

    print("test_inventory: ALL PASS")


if __name__ == "__main__":
    main()
