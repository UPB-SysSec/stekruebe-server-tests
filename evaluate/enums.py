from enum import StrEnum, IntEnum


class TlsVersion(StrEnum):
    TLSv1_2 = "TLSv1.2"
    TLSv1_3 = "TLSv1.3"


class RemoteAlias(StrEnum):
    UNKNOWN = "unknown host"
    TICKET_ISSUER = "ticket issuer host"
    RESUMPTION = "resumption host"


class RemoteRole(StrEnum):
    SNI_VALUE = "sni value"
    HOST_VALUE = "host header value"


class ResultSummary(IntEnum):
    GOOD = 0
    WARN = 1
    BAD = 3

    def __or__(self, other):
        # bitwise OR should give the worst result
        assert isinstance(other, ResultSummary)
        return max(self, other)


class BoolSummary(StrEnum):
    ALL = "all"
    SOME = "some"
    NONE = "none"

    @staticmethod
    def summarize(*bools):
        if isinstance(bools[0], bool):
            assert all(isinstance(b, bool) for b in bools)
            if all(bools):
                return BoolSummary.ALL
            elif any(bools):
                return BoolSummary.SOME
            else:
                return BoolSummary.NONE
        elif isinstance(bools[0], BoolSummary):
            assert all(isinstance(b, BoolSummary) for b in bools)
            seen_values = set(bools)
            if len(seen_values) == 1:
                return bools[0]
            # multiple values: i.e. it cannot be all or none -> some
            return BoolSummary.SOME
        else:
            raise ValueError("Unknown type")
