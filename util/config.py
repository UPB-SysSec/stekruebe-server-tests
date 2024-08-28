from pydantic import BaseModel, field_validator
import yaml
from typing import Any, Union
import jinja2
import os.path as op


class VirtualHostConfig(BaseModel):
    port: int
    hostname: str
    cert: str
    cert_key: str
    html_root: str


class ServerConfig(BaseModel):
    vHosts: list[VirtualHostConfig]


class TestcaseConfig(BaseModel):
    servers: list[ServerConfig]


class SoftwareConfig(BaseModel):
    image: str
    config_path: str
    template: str
    stek_length: int

    def render_config(self, server_cfg: ServerConfig, stek_path) -> str:
        with open(self.template) as f:
            template = jinja2.Template(f.read())
        return template.render(
            vhosts=server_cfg.vHosts,
            stek_path=stek_path,
        )


class TestConfig(BaseModel):
    test_cases: dict[str, TestcaseConfig]
    software_config: dict[str, SoftwareConfig]

    @field_validator("software_config", mode="before")
    @classmethod
    def ignore_beginning_with_underscore(cls, v: dict[str, Any]) -> dict[str, Any]:
        keys_to_remove = set()
        for key, value in v.items():
            if key.startswith("_"):
                keys_to_remove.add(key)
        for key in keys_to_remove:
            del v[key]
        return v


def parse_config_file(file_path: str) -> TestConfig:
    with open(file_path) as f:
        config = yaml.load(f, Loader=yaml.SafeLoader)
    config = TestConfig(**config)
    # fix relative paths for templates
    basedir = op.dirname(file_path)
    for software in config.software_config.values():
        software.template = op.join(basedir, software.template)
    return config


if __name__ == "__main__":
    from pprint import pprint

    with open("testcases/config.yml") as f:
        config = yaml.load(f, Loader=yaml.SafeLoader)
    print("Raw config:")
    pprint(config)
    # parse different parts
    VirtualHostConfig(**config["test_cases"]["one-server"]["servers"][0]["vHosts"][0])
    ServerConfig(**config["test_cases"]["one-server"]["servers"][0])
    TestcaseConfig(**config["test_cases"]["one-server"])
    SoftwareConfig(**config["software_config"]["nginx"])
    print("\nParsed config:")
    config = parse_config_file("testcases/config.yml")
    pprint(config)

    for sw, sw_cfg in config.software_config.items():
        print("#", sw)
        for testcase, testcase_cfg in config.test_cases.items():
            print("##", testcase)
            for i, server in enumerate(testcase_cfg.servers):
                print("###", i)
                print(sw_cfg.render_config(server, "/stek.key"))
