import itertools
from enum import Enum
from typing import Optional, Union

from pydantic import BaseModel, Field

from .enums import RemoteAlias, RemoteRole, TlsVersion


class GeneratedModel(BaseModel):
    @staticmethod
    def _get_values_for_type(typ):
        if typ == type(None):
            return [None]

        if typ == str:
            raise ValueError("Cannot generate strings")

        if typ == bool:
            return [False, True]

        if hasattr(typ, "__origin__") and typ.__origin__ == Union:
            # handle Union/Optional
            values = set()
            for arg in typ.__args__:
                values.update(TestCaseParameters._get_values_for_type(arg))
            return values

        if issubclass(typ, Enum):
            return list(typ)

        raise ValueError(f"Unknown type {typ}")

    @classmethod
    def generate(cls, **given_parameters):
        field_value_space = {}
        for field_name, field_info in cls.model_fields.items():
            if field_name in given_parameters:
                if isinstance(given_parameters[field_name], (list, tuple, set)):
                    field_value_space[field_name] = given_parameters[field_name]
                else:
                    field_value_space[field_name] = [given_parameters[field_name]]
            elif isinstance(field_info.examples, list):
                field_value_space[field_name] = field_info.examples
            else:
                field_value_space[field_name] = TestCaseParameters._get_values_for_type(field_info.annotation)

        for values in itertools.product(*field_value_space.values()):
            parameters = dict(zip(field_value_space.keys(), values))
            yield cls(**parameters)


class TestCaseParameters(GeneratedModel):
    tls_version: TlsVersion = Field(examples=list(TlsVersion))
    sni_name: Optional[RemoteAlias] = Field(examples=[RemoteAlias.TICKET_ISSUER, RemoteAlias.RESUMPTION, None])
    host_header_name: RemoteAlias = Field(examples=[RemoteAlias.TICKET_ISSUER, RemoteAlias.RESUMPTION])

    def get_roles(self, alias: RemoteAlias) -> set[RemoteRole]:
        ret = set()
        if alias == self.sni_name:
            ret.add(RemoteRole.SNI_VALUE)
        if alias == self.host_header_name:
            ret.add(RemoteRole.HOST_VALUE)
        return ret
