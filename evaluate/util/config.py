from pydantic import BaseModel, field_validator, model_validator
import yaml
from typing import Any, Union
import jinja2
import os.path as op
from typing import Optional


class VirtualHostConfig(BaseModel):
    port: int
    hostname: str
    cert: str
    cert_key: str
    html_root: str
    stek_id: Optional[str] = None
    stek_path: Optional[str] = None

    # validate that stekid and stekpath are set at the same time

    @model_validator(mode="after")
    def check_passwords_match(self):
        stek_specifiers = 0
        if self.stek_id:
            stek_specifiers += 1
        if self.stek_path:
            stek_specifiers += 1
        if stek_specifiers == 1:
            raise ValueError("stek_id and stek_path must either both be set or both be None")
        return self


class ServerConfig(BaseModel):
    vHosts: list[VirtualHostConfig]
    stek_id: str


class TestcaseConfig(BaseModel):
    servers: list[ServerConfig]

    def get_stek_ids(self) -> set[str]:
        ret = set()
        for server in self.servers:
            ret.add(server.stek_id)
            for vhost in server.vHosts:
                if vhost.stek_id:
                    ret.add(vhost.stek_id)
        return ret


class SoftwareConfig(BaseModel):
    image: str
    command: Optional[str] | list[str] = None
    config_path: str
    template: str
    stek_length: int
    additional_vhost_ports: list[int] = []
    supports_sni_none: bool = True
    extra_config_vars: dict[str, Any] = {}

    def render_config(self, server_cfg: ServerConfig, stek_path, comment=None) -> str:
        with open(self.template) as f:
            template = jinja2.Template(f.read())
        return template.render(
            **self.extra_config_vars,
            vhosts=server_cfg.vHosts,
            stek_path=stek_path,
            comment=comment,
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
    import sys
    from pprint import pprint

    with open("testcases/config.yml") as f:
        config = yaml.load(f, Loader=yaml.SafeLoader)
    print("Raw config:")
    pprint(config)
    # parse different parts
    # VirtualHostConfig(**config["test_cases"]["one-server"]["servers"][0]["vHosts"][0])
    # ServerConfig(**config["test_cases"]["one-server"]["servers"][0])
    # TestcaseConfig(**config["test_cases"]["one-server"])
    # SoftwareConfig(**config["software_config"]["nginx"])
    print("\nParsed config:")
    config = parse_config_file("testcases/config.yml")
    pprint(config)

    if len(sys.argv) == 1:
        # print all configs
        for sw, sw_cfg in config.software_config.items():
            print("#", sw)
            for testcase, testcase_cfg in config.test_cases.items():
                print("##", testcase)
                for i, server in enumerate(testcase_cfg.servers):
                    print("###", i)
                    print(sw_cfg.render_config(server, "/stek.key"))
    elif len(sys.argv) == 2:
        sw = sys.argv[1]
        print("#", sw)
        sw_cfg = config.software_config[sw]
        for testcase, testcase_cfg in config.test_cases.items():
            print("##", testcase)
            for i, server in enumerate(testcase_cfg.servers):
                print("###", i)
                print(sw_cfg.render_config(server, "/stek.key"))
    elif len(sys.argv) == 3:
        sw = sys.argv[1]
        testcase = sys.argv[2]
        sw_cfg = config.software_config[sw]
        testcase_cfg = config.test_cases[testcase]
        print("#", sw)
        print("##", testcase)
        for i, server in enumerate(testcase_cfg.servers):
            print("###", i)
            print(sw_cfg.render_config(server, "/stek.key"))
