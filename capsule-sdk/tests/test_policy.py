import pathlib

import pytest
import yaml

from capsule_sdk.policy import Policy, ValidationError

FIX = pathlib.Path(__file__).parent / "fixtures"


def load(name: str):
    return Policy.from_yaml(FIX / name)


def test_good():
    load("good_policy.yml")


@pytest.mark.parametrize("bad", ["bad_regex.yml", "rel_path.yml"])
def test_invalid(bad):
    with pytest.raises(ValidationError):
        load(bad)
