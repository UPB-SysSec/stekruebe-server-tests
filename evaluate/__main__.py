import csv
import itertools
import logging as _logging
import tempfile
import time
from abc import abstractmethod, ABC
from contextlib import ExitStack
from pathlib import Path

import click

from .util import config
from .context import EvalContext, _ALL_CTXS
from .functionality.evaluate import evaluate
from .result import SingleResult, group_results


logging = _logging.getLogger(__name__)


class TestConfigCli(click.ParamType):
    name = "testconfig"

    def convert(self, value, param, ctx):
        return config.parse_config_file(value)


class NameCliParameter(click.ParamType, ABC):
    def __init__(self, multiple_comma=True):
        self.multi_comma = multiple_comma

    def convert(self, value, param, ctx):
        testconfig = ctx.parent.params["testconfig"]
        assert isinstance(testconfig, config.TestConfig)
        dict_to_filter = self.get_dict_to_filter(testconfig)

        if self.multi_comma:
            all_items = set(map(str.strip, value.split(",")))
        else:
            all_items = {value}

        for item in all_items:
            if item not in dict_to_filter:
                raise ValueError(f"Unknown test case {item}")

        for item in list(dict_to_filter.keys()):
            if item not in all_items:
                dict_to_filter.pop(item)

        return all_items

    @abstractmethod
    def get_dict_to_filter(self, testconfig: config.TestConfig):
        raise NotImplementedError()


class TestCaseNameCli(NameCliParameter):
    name = "testcase_name"

    def get_dict_to_filter(self, testconfig: config.TestConfig):
        return testconfig.test_cases


class SoftwareNameCli(NameCliParameter):
    name = "software_name"

    def get_dict_to_filter(self, testconfig: config.TestConfig):
        return testconfig.software_config


_TESTCASES_DIR = Path(__file__).parent.parent / "testcases"


@click.group()
@click.option("--config", "testconfig", type=TestConfigCli(), default=_TESTCASES_DIR / "config.yml")
@click.option("--verbose", "-v", count=True)
def main(verbose, **kwargs):
    # click handles this
    levels = [_logging.INFO, _logging.DEBUG]
    level = levels[min(len(levels) - 1, verbose)]
    _logging.basicConfig(format="%(asctime)s %(levelname)7s | %(funcName)20s: %(message)s", level=level)
    logging.setLevel(_logging.INFO)

    pass


@main.command("evaluate")
@click.pass_context
@click.option("--software", "_software_names", type=SoftwareNameCli(), default=None)
@click.option("--case", "_testcase_names", type=TestCaseNameCli(), default=None)
# def main_evaluate(testconfig: config.TestConfig, _testcase_names, _software_names):
def main_evaluate(
    ctx: click.Context,
    _testcase_names,
    _software_names,
):
    from .functionality.evaluate import evaluate

    root_logger = _logging.getLogger()
    assert len(root_logger.handlers) == 1
    logger_formatter = root_logger.handlers[0].formatter
    file_handler = _logging.FileHandler("results.log", mode="w")
    file_handler.setFormatter(logger_formatter)
    root_logger.addHandler(file_handler)

    assert ctx.parent
    testconfig = ctx.parent.params["testconfig"]
    # testconfig = config.parse_config_file(TESTCASES_DIR / "config.yml")
    with tempfile.TemporaryDirectory(delete=True, prefix="steckruebe_") as temp_dir, open(
        "results.csv", "w"
    ) as f, open("results.jsonl", "w") as f_jsonl:

        TEMP_DIR = Path(temp_dir)
        CTX = EvalContext.make(_TESTCASES_DIR, TEMP_DIR)
        keys = None
        results = []
        for result in evaluate(testconfig, CTX):
            assert isinstance(result, SingleResult)
            results.append(result)

            # jsonl dump
            f_jsonl.write(result.model_dump_json(indent=None))
            f_jsonl.write("\n")
            f_jsonl.flush()

            # csv dump
            parameters = result.parameters
            assert isinstance(parameters, dict)
            result = result.model_dump()
            # parameters = {f"parameters.{k}": v for k, v in parameters.items()}
            result = {f"result.{k}": v for k, v in result.items() if k != "parameters"}

            if keys is None:
                # first result
                keys = parameters.keys()
                writer = csv.DictWriter(f, fieldnames=[*keys, *result.keys()])
                writer.writeheader()
            else:
                assert keys == parameters.keys(), "Different keys"
            writer.writerow(
                {
                    **parameters,
                    **result,
                }
            )

    # group results
    group_keys = (
        "software_name",
        "case_name",
        ("sni_name", "host_header_name"),
        "tls_version",
        ("issuer", "resumption"),
    )
    grouped = group_results(results, *group_keys)
    with open("results.json", "w") as f:
        f.write(grouped.model_dump_json(indent=2))


@main.command("config")
@click.pass_context
@click.argument("_software_names", type=SoftwareNameCli())
@click.argument("_testcase_names", type=TestCaseNameCli())
def main_print_config(
    ctx: click.Context,
    _testcase_names,
    _software_names,
):
    assert ctx.parent
    testconfig = ctx.parent.params["testconfig"]
    for software_name, software_cfg in testconfig.software_config.items():
        print("# Software", software_name)
        for case_name, case_cfg in testconfig.test_cases.items():
            print("## Case", case_name)
            for i, server_cfg in enumerate(case_cfg.servers):
                print("### Server", i)
                print(software_cfg.render_config(server_cfg, comment=f"Config No {i}"))


@main.command("deploy")
@click.pass_context
@click.argument("_software_names", type=SoftwareNameCli())
@click.argument("_testcase_names", type=TestCaseNameCli())
def main_deploy(
    ctx: click.Context,
    _testcase_names,
    _software_names,
):
    from .deployment import setup_server, StekRegistry

    assert ctx.parent
    testconfig = ctx.parent.params["testconfig"]

    with tempfile.TemporaryDirectory(delete=True, prefix="steckruebe_") as temp_dir, ExitStack() as stack:
        TEMP_DIR = Path(temp_dir)
        CTX = EvalContext.make(_TESTCASES_DIR, TEMP_DIR)
        for software_name, software_cfg in testconfig.software_config.items():
            for case_name, case_cfg in testconfig.test_cases.items():
                steks = StekRegistry()
                for i, server_cfg in enumerate(case_cfg.servers):
                    instance = setup_server(software_name, case_name, software_cfg, server_cfg, steks, i, CTX)
                    stack.enter_context(instance)
                    print(f" Started {instance.container.name} at https://{instance.ip}")
                    for vhost in server_cfg.vHosts:
                        print(f"  - {vhost.hostname}: https://{vhost.hostname}:{vhost.port}/")
                        print(
                            f" curl -k --resolve '*:{vhost.port}:{instance.ip}' https://{vhost.hostname}:{vhost.port}/"
                        )
        try:
            print("\nStarted all servers. Press Ctrl+C to stop.")
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            print("\rStopping...")


@main.command("postprocess")
@click.pass_context
@click.argument("input_file", type=click.File("r"), default="results.jsonl")
def post_process(ctx: click.Context, input_file):
    results: list[SingleResult] = []
    for row in input_file:
        results.append(SingleResult.model_validate_json(row))

    from .functionality.postprocess import check_result_assertions, check_table_assumptions

    # assert ctx.parent
    # from .util.config import TestConfig

    # testconfig: TestConfig = ctx.parent.params["testconfig"]
    # for case_name in testconfig.test_cases:
    #     print(f'{case_name.upper().replace("-","_")}="case_name={case_name}"')
    # for software_name in testconfig.software_config:
    #     print(f'{software_name.upper().replace("-","_")}="software_name={software_name}"')

    for _ in range(20):
        print("WARNING! IGNORING caddy_caddyfile for now")
    from .result import filter_results

    results = list(
        filter_results(
            results,
            # OLS w admin behaves like multiple ports/servers
            predicate=lambda d: d["software_name"] not in ("caddy_caddyfile"),
        )
    )

    check_result_assertions(results)
    print("\n\nChecking table assumptions")
    check_table_assumptions(results)


if __name__ == "__main__":
    main()
    for CTX in _ALL_CTXS:
        if CTX.STARTED_CONTAINER_IDS:
            logging.warning("Some containers were not removed: %s", CTX.STARTED_CONTAINER_IDS)
