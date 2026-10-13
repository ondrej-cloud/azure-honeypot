#!/usr/bin/env python3
"""One-off helper: tag world-atlas countries with ISO 3166-1 alpha-2 codes.

world-atlas identifies countries by ISO numeric id ("203" = Czechia), while the
GeoIP data used by the pipeline speaks alpha-2 ("CZ"). Baking the alpha-2 code
into the TopoJSON keeps the dashboard free of a lookup table.

It also writes pipeline/countries.json (alpha-2 -> short English name) for the
README charts, which are rendered in Python where Intl.DisplayNames is missing.

Usage: build_world_map.py countries-110m.json iso-3166.json docs/assets/world-110m.json pipeline/countries.json
  countries-110m.json  https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json
  iso-3166.json        https://github.com/lukes/ISO-3166-Countries-with-Regional-Codes (all/all.json)
"""
import json
import re
import sys

SHORT_NAMES = {"US": "United States", "CD": "DR Congo", "GB": "United Kingdom"}


def main(atlas_path: str, iso_path: str, out_path: str, names_path: str) -> None:
    with open(atlas_path, encoding="utf-8") as f:
        atlas = json.load(f)
    with open(iso_path, encoding="utf-8") as f:
        iso = json.load(f)
    numeric_to_a2 = {row["country-code"]: row["alpha-2"] for row in iso}
    # ISO names are formal ("Korea, Republic of"); Natural Earth's are what people say.
    names = {row["alpha-2"]: re.sub(r"\s*\(.*\)|,.*$", "", row["name"]) for row in iso}
    # Territories world-atlas draws without an ISO numeric id.
    by_name = {"Kosovo": "XK", "N. Cyprus": "CY", "Somaliland": "SO"}

    missing = []
    for geom in atlas["objects"]["countries"]["geometries"]:
        props = geom.setdefault("properties", {})
        cc = numeric_to_a2.get(str(geom.get("id", ""))) or by_name.get(props.get("name", ""))
        if cc:
            props["cc"] = cc
            if props.get("name") and cc != "CY":
                names[cc] = props["name"]
        else:
            missing.append(props.get("name"))
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(atlas, f, separators=(",", ":"))
    names.update(SHORT_NAMES)
    with open(names_path, "w", encoding="utf-8") as f:
        json.dump(dict(sorted(names.items())), f, ensure_ascii=False, indent=0)
    print(f"wrote {out_path} and {names_path}; untagged: {missing or 'none'}")


if __name__ == "__main__":
    main(*sys.argv[1:5])
