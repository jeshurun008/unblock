from pathlib import Path

import yaml

CONFIG_FILENAME = "unblock.config.yaml"


def config_path(cwd: str | None = None) -> Path:
    return Path(cwd or ".") / CONFIG_FILENAME


def load_config(cwd: str | None = None) -> dict:
    path = config_path(cwd)
    if not path.exists():
        return {"repos": []}
    with open(path, encoding="utf-8-sig") as f:
        # utf-8-sig transparently strips a UTF-8 BOM, which text editors on
        # Windows often prepend and which otherwise corrupts the first YAML key.
        data = yaml.safe_load(f) or {}
    data.setdefault("repos", [])
    return data


def save_config(data: dict, cwd: str | None = None) -> None:
    path = config_path(cwd)
    with open(path, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False)


def init_config(cwd: str | None = None) -> Path:
    path = config_path(cwd)
    if path.exists():
        return path
    save_config({"repos": []}, cwd)
    return path


def add_repo(name: str, path: str, cwd: str | None = None) -> None:
    data = load_config(cwd)
    data["repos"] = [r for r in data["repos"] if r["name"] != name]
    data["repos"].append({"name": name, "path": path})
    save_config(data, cwd)


def remove_repo(name: str, cwd: str | None = None) -> bool:
    data = load_config(cwd)
    before = len(data["repos"])
    data["repos"] = [r for r in data["repos"] if r["name"] != name]
    save_config(data, cwd)
    return len(data["repos"]) < before
