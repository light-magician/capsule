import pathlib
import re

from pydantic import BaseModel, Field, RootModel, ValidationError, field_validator


class Tool(BaseModel):
    argv_pattern: list[str]
    read: list[str] = Field(default_factory=list)
    write: list[str] = Field(default_factory=list)
    net: bool

    @field_validator("argv_pattern")
    @classmethod
    def check_regexes(cls, v: list[str]):
        for part in v:
            if "${" in part:
                # skipping placeholders
                continue
            try:
                re.compile(part)
            except re.error as e:
                raise ValueError(f"invalid regex in argv_pattern {e}") from e

    @field_validator("read", "write")
    @classmethod
    def abs_paths(cls, v: list[str]):
        for p in v:
            if not pathlib.Path(p).is_absolute():
                raise ValueError(f"path {p!r} must be absolute")
        return v

    def write_subset_of_read(cls, w, info):
        read_set = set(info.data.get("read", []))
        if w and not read_set.issuperset(w):
            raise ValueError("write paths must be subset of read paths")
        return w


class Policy(RootModel):
    root: dict[str, Tool]
