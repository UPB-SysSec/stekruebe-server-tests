import ssl
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional, Union

from pydantic import BaseModel, field_validator, model_serializer, model_validator

from .context import EvalContext
from .enums import BoolSummary, RemoteAlias, RemoteRole, ResultSummary, TlsVersion
from .parameters import TestCaseParameters
from .util.contextmanagedvars import ContextManagedVar
from .util.request import HttpsResponse, Remote


@dataclass
class vhostTestData:
    remote: Remote
    initial_result: HttpsResponse
    sessions: dict[TlsVersion, ssl.SSLSession]
    requires_sni: bool
    resumption_working: bool


_RemoteNameSummary_MULTIPLE = "<multiple values>"


def _try_parse_enum(value, enum_types):
    for cls in enum_types:
        try:
            return cls(value)
        except ValueError:
            continue
    return value


class RemoteNameSummary(BaseModel):
    data: set[Union[RemoteAlias, RemoteRole, str, None]]

    def __init__(self, *data):
        if len(data) == 1 and isinstance(data[0], set):
            data = data[0]
        else:
            assert not any(isinstance(d, set) for d in data)
        super().__init__(data=data)

    @field_validator("data")
    @classmethod
    def _fix_data_types(cls, v, info, *args, **kwargs):
        assert isinstance(v, set), f"Expected set, got {type(v)}"
        field_info = cls.model_fields["data"]
        annotation = field_info.annotation
        assert annotation.__origin__ == set, f"Expected set, got {annotation}"
        assert len(annotation.__args__) == 1
        annotation = annotation.__args__[0]
        assert annotation.__origin__ == Union
        return set(_try_parse_enum(d, annotation.__args__) for d in v)

    @model_validator(mode="before")
    @classmethod
    def deserialize(cls, d):
        if isinstance(d, dict) and "data" in d:
            return d
        data = None
        if isinstance(d, str):
            data = {d}
        elif isinstance(d, list):
            data = set(d)
        elif isinstance(d, set):
            data = d
        else:
            raise ValueError("Unknown Format for RemoteNameSummary")
        return {"data": data}

    @model_serializer()
    def serialize(self):
        if len(self.data) == 0:
            return _RemoteNameSummary_MULTIPLE
        if len(self.data) == 1:
            return next(iter(self.data))
        return self.data

    def __eq__(self, value: object) -> bool:
        if isinstance(value, RemoteNameSummary):
            return self.data == value.data
        if isinstance(value, set):
            return self.data == value
        if isinstance(value, list):
            return self.data == set(value)
        if len(self.data) == 1:
            return next(iter(self.data)) == value
        return False

    def __contains__(self, value: object) -> bool:
        return value in self.data

    @staticmethod
    def from_body(
        received,
        ticket_issuer_host: vhostTestData,
        resumption_host: vhostTestData,
        abstract_parameters: "TestCaseParameters",
    ):
        # assert (
        #     ticket_issuer_host.initial_result.body != resumption_host.initial_result.body
        # ), "Same body for ticket and resumption; should've been caught earlier"
        if ticket_issuer_host.initial_result.body == resumption_host.initial_result.body:
            return RemoteNameSummary(
                ticket_issuer_host.remote.hostname,
                RemoteAlias.TICKET_ISSUER,
                *abstract_parameters.get_roles(RemoteAlias.TICKET_ISSUER),
                resumption_host.remote.hostname,
                RemoteAlias.RESUMPTION,
                *abstract_parameters.get_roles(RemoteAlias.RESUMPTION),
            )
        if received == ticket_issuer_host.initial_result.body:
            return RemoteNameSummary(
                ticket_issuer_host.remote.hostname,
                RemoteAlias.TICKET_ISSUER,
                *abstract_parameters.get_roles(RemoteAlias.TICKET_ISSUER),
            )
        elif received == resumption_host.initial_result.body:
            return RemoteNameSummary(
                resumption_host.remote.hostname,
                RemoteAlias.RESUMPTION,
                *abstract_parameters.get_roles(RemoteAlias.RESUMPTION),
            )
        else:
            return RemoteNameSummary(RemoteAlias.UNKNOWN)

    @staticmethod
    def summarize(*remote_names):
        remote_names = list(remote_names)
        for i in range(len(remote_names)):
            if isinstance(remote_names[i], RemoteNameSummary):
                remote_names[i] = remote_names[i].data
            elif not isinstance(remote_names[i], set):
                # assume single value
                remote_names[i] = {remote_names[i]}

        ret = set(remote_names[0])
        for r in remote_names[1:]:
            ret.intersection_update(r)
        return RemoteNameSummary(ret)


assert RemoteNameSummary.summarize("a", "a").model_dump() == "a"
assert RemoteNameSummary.summarize("a", "b").model_dump() == _RemoteNameSummary_MULTIPLE
assert (
    RemoteNameSummary.summarize(RemoteAlias.RESUMPTION, RemoteAlias.RESUMPTION).model_dump() == RemoteAlias.RESUMPTION
)
assert (
    RemoteNameSummary.summarize(RemoteAlias.RESUMPTION, RemoteAlias.TICKET_ISSUER).model_dump()
    == _RemoteNameSummary_MULTIPLE
)
_A_ISS = RemoteNameSummary(RemoteAlias.TICKET_ISSUER, "a")
_A_RES = RemoteNameSummary(RemoteAlias.RESUMPTION, "a")
_B_ISS = RemoteNameSummary(RemoteAlias.TICKET_ISSUER, "b")
_B_RES = RemoteNameSummary(RemoteAlias.RESUMPTION, "b")
assert RemoteNameSummary.summarize(_A_ISS, _A_ISS).model_dump() == RemoteNameSummary(RemoteAlias.TICKET_ISSUER, "a")
assert RemoteNameSummary.summarize(_A_ISS, _A_RES).model_dump() == "a"
assert RemoteNameSummary.summarize(_A_ISS, _B_ISS).model_dump() == RemoteAlias.TICKET_ISSUER
assert RemoteNameSummary.summarize(_A_ISS, _B_RES).model_dump() == _RemoteNameSummary_MULTIPLE
del _A_ISS, _A_RES, _B_ISS, _B_RES


class SingleResult(BaseModel):
    parameters: dict[str, Any]
    summary: ResultSummary
    ticket_resumed: bool
    body: Optional[RemoteNameSummary]
    response_status_code: Optional[int]
    response_body: Optional[bytes]
    full_response_cert: Optional[RemoteNameSummary]
    full_response_body: Optional[RemoteNameSummary]
    full_body_equals_resumption_body: Optional[bool]
    full_body_equals_cert: Optional[bool]

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, SingleResult):
            return False
        ignored_fields = SingleResult.__eq__.ignoredFields.get()  # type: ignore[attr-defined]
        for field in self.model_fields:
            if field in ignored_fields:
                continue
            if getattr(self, field) != getattr(value, field):
                return False
        return True

    @staticmethod
    def from_response(
        abstract_parameters: TestCaseParameters,
        concrete_parameters: dict[str, Any],
        resumption_response: Optional[HttpsResponse],
        full_response: Optional[HttpsResponse],
        ticket_issuer: vhostTestData,
        resumption: vhostTestData,
        CTX: EvalContext,
    ):
        if full_response is None:
            assert resumption_response is None
            return SingleResult(
                parameters=concrete_parameters,
                summary=ResultSummary.GOOD,
                ticket_resumed=False,
                body=None,
                response_status_code=None,
                response_body=None,
                full_response_cert=None,
                full_response_body=None,
                full_body_equals_resumption_body=False,
                full_body_equals_cert=False,
            )
        assert resumption_response
        body_remote = RemoteNameSummary.from_body(
            resumption_response.body, ticket_issuer, resumption, abstract_parameters
        )
        full_response_body_remote = RemoteNameSummary.from_body(
            full_response.body, ticket_issuer, resumption, abstract_parameters
        )

        if full_response.cert == CTX.CERTS[ticket_issuer.remote.hostname]:
            full_response_cert = RemoteNameSummary(
                RemoteAlias.TICKET_ISSUER,
                ticket_issuer.remote.hostname,
                *abstract_parameters.get_roles(RemoteAlias.TICKET_ISSUER),
            )
        elif full_response.cert == CTX.CERTS[resumption.remote.hostname]:
            full_response_cert = RemoteNameSummary(
                RemoteAlias.RESUMPTION,
                resumption.remote.hostname,
                *abstract_parameters.get_roles(RemoteAlias.RESUMPTION),
            )
        else:
            for name, cert in CTX.CERTS.items():
                if full_response.cert == cert:
                    full_response_cert = RemoteNameSummary(name)
                    break
            else:
                full_response_cert = RemoteNameSummary(RemoteAlias.UNKNOWN)

        summary = None
        if not resumption_response.session_reused:
            summary = ResultSummary.GOOD
        else:
            # session was reused
            if RemoteAlias.TICKET_ISSUER in body_remote:
                summary = ResultSummary.GOOD
            elif RemoteAlias.RESUMPTION in body_remote:
                summary = ResultSummary.BAD
            else:
                # unknown body
                summary = ResultSummary.WARN

        return SingleResult(
            parameters=concrete_parameters,
            ticket_resumed=resumption_response.session_reused,
            body=body_remote,
            summary=summary,
            response_status_code=resumption_response.response.status,
            response_body=resumption_response.body,
            full_response_cert=full_response_cert,
            full_response_body=full_response_body_remote,
            full_body_equals_resumption_body=full_response.body == resumption_response.body,
            full_body_equals_cert=full_response_cert == full_response_body_remote,
        )


SingleResult.__eq__.ignoredFields = ContextManagedVar("SingleResultEqualityIgnoredFields", default={"parameters"})  # type: ignore[attr-defined]


class GroupedResult(BaseModel):
    summary: ResultSummary
    ticket_resumed: BoolSummary
    body: RemoteNameSummary

    full_response_cert: RemoteNameSummary
    full_response_body: RemoteNameSummary
    full_body_equals_resumption_body: BoolSummary
    full_body_equals_cert: BoolSummary
    details: dict[Any, Union["GroupedResult", SingleResult]] | list[SingleResult]

    def __getitem__(self, key):
        return self.details[key]

    def items(self):
        return self.details.items()

    def keys(self):
        return self.details.keys()

    def walk_results(self):
        if isinstance(self.details, list):
            iterable = self.details
        elif isinstance(self.details, dict):
            iterable = self.details.values()
        for r in iterable:
            if isinstance(r, SingleResult):
                yield r
            elif isinstance(r, GroupedResult):
                yield from r.walk_results()

    @staticmethod
    def from_results(results: dict[Any, Union["GroupedResult", SingleResult]] | list[SingleResult]):
        result_values: list[GroupedResult | SingleResult]
        if isinstance(results, list):
            result_values = list(results)
        elif isinstance(results, dict):
            result_values = list(results.values())
        else:
            raise ValueError("Unknown type for results")

        while None in result_values:
            result_values.remove(None)  # type: ignore
        if not result_values:
            return None
        assert all(isinstance(r, (SingleResult, GroupedResult)) for r in result_values)

        summary = ResultSummary.GOOD
        for result in result_values:
            summary |= result.summary
        return GroupedResult(
            summary=summary,
            ticket_resumed=BoolSummary.summarize(*(r.ticket_resumed for r in result_values)),
            body=RemoteNameSummary.summarize(*(r.body for r in result_values)),
            full_response_cert=RemoteNameSummary.summarize(*(r.full_response_cert for r in result_values)),
            full_response_body=RemoteNameSummary.summarize(*(r.full_response_body for r in result_values)),
            full_body_equals_resumption_body=BoolSummary.summarize(
                *(r.full_body_equals_resumption_body for r in result_values)
            ),
            full_body_equals_cert=BoolSummary.summarize(*(r.full_body_equals_cert for r in result_values)),
            details=results,
        )


def group_results(results: Iterable[SingleResult], *group_keys, _used_keys=None):
    """Groups results by given keys (from parameters). Keys may be single strings or multiple strings in a tuple."""
    """This works in two phases:
    1. (As long as there are remaining keys) create a structure which contains the plain results grouped by the current key
    For example in the first round:
    {
        "identifier1": [result1, result2, ...],
        "identifier2": [result3, result4, ...],
    }
    And in the second round:
    {
        "identifier1": {
            "identifier1.1": [result1, result2, ...],
            "identifier1.2": [result3, result4, ...],
        },
        "identifier2": {
            "identifier2.1": [result5, result6, ...],
            "identifier2.2": [result7, result8, ...],
        },
    }

    2. (When there are no more keys) create a GroupedResult from the grouped results
    """
    if _used_keys is None:
        _used_keys = set()
    else:
        _used_keys = set(_used_keys)

    current_key = group_keys[0]
    remaining_keys = group_keys[1:]

    if isinstance(current_key, tuple):
        for key in current_key:
            assert key not in _used_keys, "Key used multiple times"
            _used_keys.add(key)
    else:
        assert current_key not in _used_keys, "Key used multiple times"
        _used_keys.add(current_key)

    grouped: dict = {}
    for result in results:
        if isinstance(current_key, tuple):
            identifier = ", ".join(f"{k}={result.parameters[k]}" for k in current_key)
        else:
            identifier = f"{current_key}={result.parameters[current_key]}"

        if identifier not in grouped:
            grouped[identifier] = []
        grouped[identifier].append(result)

    if remaining_keys:
        for identifier in grouped:
            grouped[identifier] = group_results(grouped[identifier], *remaining_keys, _used_keys=_used_keys)
    else:
        for identifier in grouped:
            if len(grouped[identifier]) == 1:
                grouped[identifier] = grouped[identifier][0]
            else:
                grouped[identifier] = GroupedResult.from_results(grouped[identifier])
    return GroupedResult.from_results(grouped)


def filter_results(
    results: list[SingleResult], *, predicate: Optional[Callable[[dict[str, Any]], bool]] = None, **kwargs
):
    for result in results:
        if predicate is not None and not predicate(result.parameters):
            # predicate does not match -> skip
            continue
        for key, value in kwargs.items():
            # skip result if result parameter does not match expected value
            if isinstance(value, set):
                if result.parameters[key] not in value:
                    break
            elif result.parameters[key] != value:
                break
        else:
            # did not break -> kwargs match
            yield result


if __name__ == "__main__":
    a = SingleResult(
        parameters={"a": 1},
        summary=ResultSummary.GOOD,
        ticket_resumed=False,
        body=None,
        response_status_code=None,
        response_body=None,
        full_response_cert=None,
        full_response_body=None,
        full_body_equals_resumption_body=False,
        full_body_equals_cert=False,
    )
    _b = a.model_dump()
    _b["ticket_resumed"] = True
    b = SingleResult(**_b)

    assert a != b
    with SingleResult.__eq__.ignoredFields.add("ticket_resumed"):  # type: ignore[attr-defined]
        assert a == b
    assert a != b
