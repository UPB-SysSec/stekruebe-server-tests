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
    CADDY = "software_name=caddy"
    CADDY_STRICT = "software_name=caddy_strict"


_NGINX = {SW.NGINX, SW.NGINX80, SW.NGINX_STRICT_HTTP_ERR, SW.NGINX_STRICT_TLS_ERR}
_APACHE = {SW.APACHE, SW.APACHE_STRICT}
_CADDY = {SW.CADDY, SW.CADDY_STRICT}


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

    # ASSERT: two-server cases do not resume tickets
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

    err.assert_true(
        grouped[SW.CADDY][CASE.ONE_SERVER] != grouped[SW.CADDY_STRICT][CASE.ONE_SERVER], 
        "caddy strict should behave differently when Host header mismatch"
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


def _check_table_assumptions_resumes_ticket(results: list[SingleResult]):
    # column: SNI=I : yes
    grouped = GroupedResult.from_results(list(filter_results(results, sni_name=RemoteAlias.TICKET_ISSUER)))
    assert grouped.ticket_resumed == BoolSummary.ALL

    # column: SNI=R
    grouped = group_results(list(filter_results(results, sni_name=RemoteAlias.RESUMPTION)), "software_name")
    ## SNI=R [nginx] : yes
    for sw in _NGINX:
        assert grouped[sw].ticket_resumed == BoolSummary.ALL
    ## SNI=R [apache, ols] : no
    for sw in _APACHE:
        assert grouped[sw].ticket_resumed == BoolSummary.NONE
    assert grouped[SW.OPENLITESPEED].ticket_resumed == BoolSummary.NONE

    # column: SNI=none
    grouped = group_results(list(filter_results(results, sni_name=None)), "software_name", "issuer")
    ## SNI=none [apache]: first host
    for sw in _APACHE:
        for issuer, issuer_grouped in grouped[sw].items():
            if issuer == "issuer=a.com":
                assert issuer_grouped.ticket_resumed == BoolSummary.ALL
            else:
                assert issuer_grouped.ticket_resumed == BoolSummary.NONE
    ## SNI=none [nginx]: yes
    ## SNI=none [nginx_strict_tls]: no
    for sw in _NGINX:
        if sw == SW.NGINX_STRICT_TLS_ERR:
            # as the TLS handshake failed, there is no result stored
            assert sw not in grouped.keys()
        else:
            assert grouped[sw].ticket_resumed == BoolSummary.ALL
    ## SNI=none [OLS]: no
    assert grouped[SW.OPENLITESPEED].ticket_resumed == BoolSummary.NONE

    print("[+] Validated Table assumptions for Resumes Ticket")


def _check_table_assumptions_resumption_content(results: list[SingleResult]):
    results = list(filter(lambda r: r.ticket_resumed, results))

    # column: SNI=I, Host=I: I
    grouped = GroupedResult.from_results(
        list(filter_results(results, sni_name=RemoteAlias.TICKET_ISSUER, host_header_name=RemoteAlias.TICKET_ISSUER))
    )
    for r in grouped.walk_results():
        assert RemoteAlias.TICKET_ISSUER in r.body
    assert RemoteAlias.TICKET_ISSUER in grouped.body

    # column: SNI=I, Host=R
    grouped = group_results(
        list(filter_results(results, sni_name=RemoteAlias.TICKET_ISSUER, host_header_name=RemoteAlias.RESUMPTION)),
        "software_name",
    )
    ## [apache] 421
    for sw in _APACHE:
        for r in grouped[sw].details:
            assert r.response_status_code == 421
    ## [nginx] R
    for sw in _NGINX:
        assert RemoteAlias.RESUMPTION in grouped[sw].body
    ## [OLS] R
    assert RemoteAlias.RESUMPTION in grouped[SW.OPENLITESPEED].body

    # column: SNI=R, Host=I
    grouped = group_results(
        list(filter_results(results, sni_name=RemoteAlias.RESUMPTION, host_header_name=RemoteAlias.TICKET_ISSUER)),
        "software_name",
    )
    ## [apache, ols]: not resumed
    for sw in _APACHE:
        assert sw not in grouped.keys()
    assert SW.OPENLITESPEED not in grouped.keys()
    ## [nginx]: I
    for sw in _NGINX:
        assert RemoteAlias.TICKET_ISSUER in grouped[sw].body

    # column: SNI=R, Host=R
    grouped = group_results(
        list(filter_results(results, sni_name=RemoteAlias.RESUMPTION, host_header_name=RemoteAlias.RESUMPTION)),
        "software_name",
    )
    ## [apache, ols]: not resumed
    for sw in _APACHE:
        assert sw not in grouped.keys()
    assert SW.OPENLITESPEED not in grouped.keys()
    ## [nginx]: I
    for sw in _NGINX:
        assert RemoteAlias.RESUMPTION in grouped[sw].body

    # column: SNI=None, Host=I
    grouped = group_results(
        list(filter_results(results, sni_name=None, host_header_name=RemoteAlias.TICKET_ISSUER)),
        "software_name",
        "tls_version",
    )
    ## apache
    for sw in _APACHE:
        for r in grouped[sw].walk_results():
            # others were not resumed
            assert r.parameters["issuer"] == "a.com"
    ### normal: I [only for first host]
    assert RemoteAlias.TICKET_ISSUER in grouped[SW.APACHE].body
    ### strict: 1.2: I, 1.3: 403
    assert RemoteAlias.TICKET_ISSUER in grouped[SW.APACHE_STRICT]["tls_version=TLSv1.2"].body
    for r in grouped[SW.APACHE_STRICT]["tls_version=TLSv1.3"].details:
        assert r.response_status_code == 403
    ## nginx: I
    ### strict: not resumed
    for sw in _NGINX:
        if sw == SW.NGINX_STRICT_TLS_ERR:
            # as the TLS handshake failed, there is no result stored
            assert sw not in grouped.keys()
        else:
            assert RemoteAlias.TICKET_ISSUER in grouped[sw].body
    ## OLS: not resumed
    assert SW.OPENLITESPEED not in grouped.keys()

    # column: SNI=None, Host=R
    grouped = group_results(
        list(filter_results(results, sni_name=None, host_header_name=RemoteAlias.RESUMPTION)),
        "software_name",
        "tls_version",
    )
    ## apache
    for sw in _APACHE:
        for r in grouped[sw].walk_results():
            # others were not resumed
            assert r.parameters["issuer"] == "a.com"
    ### normal: 1.2: 421, 1.3: R
    for r in grouped[SW.APACHE]["tls_version=TLSv1.2"].walk_results():
        assert r.response_status_code == 421
    assert RemoteAlias.RESUMPTION in grouped[SW.APACHE]["tls_version=TLSv1.3"].body
    ### strict: 1.2: 421, 1.3: 403
    for r in grouped[SW.APACHE_STRICT]["tls_version=TLSv1.2"].walk_results():
        assert r.response_status_code == 421
    for r in grouped[SW.APACHE_STRICT]["tls_version=TLSv1.3"].walk_results():
        assert r.response_status_code == 403

    ## nginx
    for sw in _NGINX:
        if sw == SW.NGINX_STRICT_TLS_ERR:
            ### strict: not resumed
            # as the TLS handshake failed, there is no result stored
            assert sw not in grouped.keys()
        else:
            ### normal: R
            assert RemoteAlias.RESUMPTION in grouped[sw].body
    ## OLS: not resumed
    assert SW.OPENLITESPEED not in grouped.keys()

    print("[+] Validated Table assumptions for Resumption Content")


def check_table_assumptions(results: list[SingleResult]):
    results = list(
        filter_results(
            results,
            case_name="one-server",
            # OLS w admin behaves like multiple ports/servers
            predicate=lambda d: d["software_name"] != "openlitespeed_w_admin",
        )
    )
    _check_table_assumptions_resumes_ticket(results)
    _check_table_assumptions_resumption_content(results)
