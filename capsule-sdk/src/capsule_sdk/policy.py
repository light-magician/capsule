import pathlib
import re

import yaml
from pydantic import BaseModel, Field, RootModel, ValidationError, field_validator


class Tool(BaseModel):
    argv_pattern: list[str]
    read: list[str] = Field(default_factory=list)
    write: list[str] = Field(default_factory=list)
    net: bool

    @field_validator("argv_pattern")
    @classmethod
    def _valid_regex(cls, v: list[str]):
        for p in v:
            if "${" in p:
                # skipping placeholders
                continue
            try:
                re.compile(p)
            except re.error as e:
                raise ValueError(f"invalid regex in argv_pattern {e}") from e

    @field_validator("read", "write")
    @classmethod
    def _abs_paths(cls, v: list[str]):
        for p in v:
            if not pathlib.Path(p).is_absolute():
                raise ValueError(f"path {p!r} must be absolute")
        return v

    @field_validator("write")
    def _write_subset(cls, w: list[str], info):
        read_list = info.data.get("read", [])

        def root_prefix(pat: str) -> str:
            # Strip off any glob/meta characters to get the directory root.
            # e.g. "/foo/bar/**/*.png" → "/foo/bar/"
            for sep in ("*", "?", "["):
                idx = pat.find(sep)
                if idx != -1:
                    pat = pat[:idx]
            return pat

        prefixes = [root_prefix(r) for r in read_list]

        # Examples for future readers:
        #   read_list = ["/data/images/**/*.png"]
        #     → prefixes = ["/data/images/"]
        #
        # OLD strict check:
        #   write = ["/data/images/**/*.jpg"]
        #     ✗ fails because "*.jpg" ≠ "*.png" even though it’s under /data/images/
        #
        # NEW prefix check:
        #   write = ["/data/images/2025/shot1.jpg"]
        #     ✓ passes because "/data/images/2025/shot1.jpg".startswith("/data/images/")
        #
        #   write = ["/other/place/file.jpg"]
        #     ✗ fails because it doesn’t start with any read‐prefix

        for path in w:
            if not any(path.startswith(pref) for pref in prefixes):
                raise ValueError("write paths must be subset of read paths")
        return w


class Policy(BaseModel):
    version: str
    tools: dict[str, Tool]

    @classmethod
    def from_yaml(cls, path: str | pathlib.Path):
        return cls.model_validate(yaml.safe_load(pathlib.Path(path).read_text()))
