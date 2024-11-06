import itertools
from dataclasses import field, dataclass
from typing import Any

from ..result import BoolSummary, GroupedResult, SingleResult, filter_results, group_results
from ..enums import RemoteAlias, RemoteRole

Error = Any
AnyResult = SingleResult | GroupedResult


class EXPECT:
    SAME = "should be same"
    DIFF = "should be different"


class COLOR:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


@dataclass
class ErrorHolder:
    expected_errors: list[Error]
    found_unexpected_errors: list[Error] = field(default_factory=list)
    found_expected_errors: list[Error] = field(default_factory=list)

    @property
    def expected_errors_not_found(self):
        return set(self.expected_errors) - set(self.found_expected_errors)

    def __bool__(self):
        return bool(self.found_unexpected_errors) or bool(self.expected_errors_not_found)

    def assert_true(self, condition: bool, message: str, error: Error = None):
        if error is None:
            error = message

        level = "+"
        col = COLOR.OKGREEN
        if not condition:
            if error in self.expected_errors:
                self.found_expected_errors.append(error)
                level = " "
                col = COLOR.OKBLUE
            else:
                self.found_unexpected_errors.append(error)
                level = "!"
                col = COLOR.FAIL
        print(f"{col}[{level}] {message}{COLOR.ENDC}")

    def assert_same_results(self, grouped: GroupedResult, prefix: str, k1: str, k2: str):
        self.assert_true(
            grouped[k1] == grouped[k2],
            f"{prefix}: {k1} and {k2} should have same results",
            (prefix, EXPECT.SAME, k1, k2),
        )

    def assert_diff_results(self, grouped: GroupedResult, prefix: str, k1: str, k2: str):
        self.assert_true(
            grouped[k1] != grouped[k2],
            f"{prefix}: {k1} and {k2} should have different results",
            (prefix, EXPECT.DIFF, k1, k2),
        )


class CASE:
    ONE_SERVER = "case_name=one-server"
    ONE_SERVER_DIFFERENT_STEKS = "case_name=one-server-different-steks"
    ONE_SERVER_DIFFERENT_PORTS = "case_name=one-server-different-ports"
    TWO_SERVERS_SAME_STEK = "case_name=two-servers-same-stek"
    TWO_SERVERS_SAME_STEK_DIFFERENT_PORTS = "case_name=two-servers-same-stek-different-ports"
    TWO_SERVERS_DISTINCT_STEK = "case_name=two-servers-distinct-stek"
    TWO_SERVERS_DISTINCT_STEK_DIFFERENT_PORTS = "case_name=two-servers-distinct-stek-different-ports"


class SW:
    NGINX = "software_name=nginx"
    NGINX80 = "software_name=nginx80"
    NGINX_STRICT_HTTP_ERR = "software_name=nginx_strict_http_err"
    NGINX_STRICT_TLS_ERR = "software_name=nginx_strict_tls_err"
    APACHE = "software_name=apache"
    APACHE_STRICT = "software_name=apache_strict"
    OPENLITESPEED = "software_name=openlitespeed"
    OPENLITESPEED_W_ADMIN = "software_name=openlitespeed_w_admin"


def check_result_assertions(results: list[SingleResult]):
    """we assert that
    - each software behaves the same in each tls version (with the exception of apache...)
    - nginx and nginx80 behave the same
    - the OLS admin interface does not resume tickets from other hosts (with the exception of the admin interface on the other host)

    This ensures we did not just assume this, but that this is actually true.
    """
    err = ErrorHolder(
        [
            "issuer=additional_0_7080, resumption=additional_1_7080: openlitespeed Admin interface should not resume",
            "issuer=additional_1_7080, resumption=additional_0_7080: openlitespeed Admin interface should not resume",
            (SW.APACHE, EXPECT.SAME, "tls_version=TLSv1.2", "tls_version=TLSv1.3"),
            (SW.APACHE_STRICT, EXPECT.SAME, "tls_version=TLSv1.2", "tls_version=TLSv1.3"),
            "software_name=nginx_strict_http_err case_name=two-servers-same-stek should not resume tickets",
            "software_name=nginx_strict_http_err case_name=two-servers-same-stek-different-ports should not resume tickets",
            "software_name=openlitespeed_w_admin case_name=two-servers-same-stek should not resume tickets",
            "software_name=openlitespeed_w_admin case_name=two-servers-same-stek-different-ports should not resume tickets",
        ]
    )

    # ASSERT: TLS 1.2 and 1.3 behave the same
    grouped = group_results(results, "software_name", "tls_version")
    for sw, sw_grouped in grouped.items():
        for k1, k2 in itertools.combinations(sw_grouped.keys(), 2):
            err.assert_same_results(sw_grouped, f"{sw}", k1, k2)

    # ASSERT: nginx with stek 48 and 80 behave the same
    grouped = group_results(results, "software_name")
    err.assert_same_results(grouped, "Software", SW.NGINX, SW.NGINX80)

    # ASSERT: OLS Admin interface does not resume tickets from other hosts
    grouped = group_results(filter_results(results, software_name="openlitespeed_w_admin"), ("issuer", "resumption"))
    for k in grouped.keys():
        if "resumption=additional_" not in k:
            continue
        err.assert_true(
            grouped[k].ticket_resumed == BoolSummary.NONE, f"{k}: openlitespeed Admin interface should not resume"
        )

    # ASSERT: We can group tests that cause the same results
    grouped = group_results(results, "software_name", "case_name")
    grouped_w_sni = group_results(
        filter_results(results, predicate=lambda d: d["sni_name"] is not None), "software_name", "case_name"
    )
    behavior_groups_per_sw = {
        None: [
            {
                CASE.ONE_SERVER,
                CASE.ONE_SERVER_DIFFERENT_STEKS,
            },
            {
                CASE.ONE_SERVER_DIFFERENT_PORTS,
                CASE.TWO_SERVERS_SAME_STEK,
                CASE.TWO_SERVERS_SAME_STEK_DIFFERENT_PORTS,
                CASE.TWO_SERVERS_DISTINCT_STEK,
                CASE.TWO_SERVERS_DISTINCT_STEK_DIFFERENT_PORTS,
            },
        ],
        SW.NGINX_STRICT_HTTP_ERR: [
            # here it makes a difference whether two servers share a stek
            {
                CASE.ONE_SERVER,
                CASE.ONE_SERVER_DIFFERENT_STEKS,
            },
            {
                CASE.ONE_SERVER_DIFFERENT_PORTS,
                CASE.TWO_SERVERS_SAME_STEK,
                CASE.TWO_SERVERS_SAME_STEK_DIFFERENT_PORTS,
            },
            {
                CASE.TWO_SERVERS_DISTINCT_STEK,
                CASE.TWO_SERVERS_DISTINCT_STEK_DIFFERENT_PORTS,
            },
        ],
        SW.OPENLITESPEED_W_ADMIN: [
            # here it makes a difference whether two servers share a stek as the admin interface allows resumptions with the same stek
            # also: one and two server scenarios are not comparable as each server adds a new vhost
            {
                CASE.ONE_SERVER,
                CASE.ONE_SERVER_DIFFERENT_STEKS,  # not supported; is just ONE_SERVER
            },
            {
                CASE.ONE_SERVER_DIFFERENT_PORTS,
            },
            {
                CASE.TWO_SERVERS_SAME_STEK,
                CASE.TWO_SERVERS_SAME_STEK_DIFFERENT_PORTS,
            },
            {
                CASE.TWO_SERVERS_DISTINCT_STEK,
                CASE.TWO_SERVERS_DISTINCT_STEK_DIFFERENT_PORTS,
            },
        ],
    }
    for behavior_groups in behavior_groups_per_sw.values():
        for s1, s2 in itertools.combinations(behavior_groups, 2):
            assert s1.isdisjoint(s2), "Behavior groups are not disjoint"

    for sw, sw_grouped in grouped.items():
        behavior_groups = behavior_groups_per_sw.get(sw, behavior_groups_per_sw[None])
        for k1, k2 in itertools.combinations(sw_grouped.keys(), 2):
            for g in behavior_groups:
                if k1 in g:
                    if k2 in g:
                        err.assert_same_results(sw_grouped, f"{sw}", k1, k2)
                    else:
                        err.assert_diff_results(sw_grouped, f"{sw}", k1, k2)
                    break
            else:
                assert False, f"Unknown behavior group for {k1} ({sw})"

    for sw, sw_grouped in grouped.items():
        for case_name, case_grouped in sw_grouped.items():
            if case_name.startswith(CASE.ONE_SERVER):
                continue
            err.assert_true(
                case_grouped.ticket_resumed == BoolSummary.NONE, f"{sw} {case_name} should not resume tickets"
            )

    # ASSERT: some other claims per software
    err.assert_true(
        grouped[SW.NGINX][CASE.ONE_SERVER].ticket_resumed == BoolSummary.ALL,
        "nginx one-server resumes all tickets",
    )
    err.assert_true(
        grouped[SW.NGINX][CASE.ONE_SERVER].body == RemoteRole.HOST_VALUE,
        "nginx one-server determines content by host header",
    )
    err.assert_true(
        grouped[SW.NGINX][CASE.ONE_SERVER_DIFFERENT_PORTS].ticket_resumed == BoolSummary.NONE,
        "nginx does not resume across ports",
    )

    err.assert_true(
        grouped_w_sni[SW.NGINX][CASE.ONE_SERVER] == grouped_w_sni[SW.NGINX_STRICT_HTTP_ERR][CASE.ONE_SERVER],
        "nginx one-server should be same (in cases with SNI) for default config and strict config (HTTP ERR)",
    )
    err.assert_true(
        grouped_w_sni[SW.NGINX][CASE.ONE_SERVER] == grouped_w_sni[SW.NGINX_STRICT_TLS_ERR][CASE.ONE_SERVER],
        "nginx one-server should be same (in cases with SNI) for default config and strict config (TLS ERR)",
    )
    err.assert_true(
        grouped[SW.NGINX_STRICT_TLS_ERR][CASE.ONE_SERVER_DIFFERENT_PORTS].ticket_resumed == BoolSummary.NONE,
        "nginx with strict config (TLS ERR) rejects all tickets on different ports (=> also for separate servers)",
    )

    err.assert_true(
        grouped_w_sni[SW.APACHE][CASE.ONE_SERVER] == grouped_w_sni[SW.APACHE_STRICT][CASE.ONE_SERVER],
        "apache one-server should be same (in cases with SNI) for default config and strict config",
    )
    err.assert_true(
        grouped[SW.APACHE][CASE.ONE_SERVER] != grouped_w_sni[SW.APACHE_STRICT][CASE.ONE_SERVER],
        "apache one-server should be differ (for SNI=None) for default config and strict config",
    )

    # Check that no unexpected errors were found
    if err.found_expected_errors:
        print(f"\n{COLOR.OKBLUE}{COLOR.UNDERLINE}[!] Errors that were expected and found:{COLOR.ENDC}")
        for error in err.found_expected_errors:
            print(error)

    if err.found_unexpected_errors:
        print(f"\n{COLOR.FAIL}{COLOR.UNDERLINE}[!] Unexpected Errors:{COLOR.ENDC}")
        for error in err.found_unexpected_errors:
            print(error)

    if err.expected_errors_not_found:
        print(f"\n{COLOR.FAIL}{COLOR.UNDERLINE}[!] Expected Errors that were not found:{COLOR.ENDC}")
        for error in err.expected_errors_not_found:
            print(error)

    assert not err, "Errors found (or expected errors were not found)"
