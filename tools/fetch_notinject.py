"""Materialise the NotInject benign dataset into corpus/benign/notinject.yaml.

NotInject (MIT) is 339 benign prompts in three difficulty splits, graded by
trigger-word density. We reference it rather than vendoring it, so this script is
required before the false-positive numbers on the NotInject stratum can be
reproduced. The materialised file is gitignored.

Usage:
    uv pip install datasets
    uv run python tools/fetch_notinject.py
"""

from __future__ import annotations

from pathlib import Path

import yaml

OUT = Path(__file__).resolve().parents[1] / "corpus" / "benign" / "notinject.yaml"
SPLITS = ("NotInject_one", "NotInject_two", "NotInject_three")


def main() -> None:
    from datasets import load_dataset  # imported lazily; not a runtime dependency

    records: list[dict[str, object]] = []
    for index, split in enumerate(SPLITS, start=1):
        dataset = load_dataset("leolee99/NotInject", split=split)
        for row_index, row in enumerate(dataset):
            records.append(
                {
                    "id": f"TW-NI-{index}-{row_index:04d}",
                    "text": row["prompt"],
                    "stratum": "notinject",
                    "difficulty": f"level_{index}",
                    "source": {
                        "name": "NotInject",
                        "url": "https://huggingface.co/datasets/leolee99/NotInject",
                        "license": "MIT",
                    },
                }
            )
    OUT.write_text(
        yaml.safe_dump({"records": records}, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
        newline="\n",
    )
    print(f"wrote {len(records)} records to {OUT}")


if __name__ == "__main__":
    main()
