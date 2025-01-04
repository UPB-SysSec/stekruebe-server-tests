import contextvars

from typing import TypeVar, overload, Generic

_T = TypeVar("_T")
_D = TypeVar("_D")


class ContextManagedVarCTX:
    def __init__(self, var, value):
        self.var = var
        self.value = value
        self.reset_token = None

    def __enter__(self):
        self.reset_token = self.var.set(self.value)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.var.reset(self.reset_token)


class ContextManagedVar(Generic[_T]):
    @overload
    def __init__(self, name: str) -> None: ...
    @overload
    def __init__(self, name: str, default: _T) -> None: ...

    def __init__(self, name, default=None):
        self.name = name
        self.var = contextvars.ContextVar(name, default=default)

    @overload
    def get(self) -> _T: ...

    @overload
    def get(self, default: _T, /) -> _T: ...

    @overload
    def get(self, default: _D, /) -> _D | _T: ...

    def get(self, *args, **kwargs):
        return self.var.get(*args, **kwargs)

    def __hash__(self):
        return hash(self.var)

    def __call__(self, value):
        return ContextManagedVarCTX(self.var, value)

    def add(self, *values):
        current_var = self.get()
        new_value = None
        if isinstance(current_var, list):
            new_value = current_var.copy()
            new_value.extend(values)
        elif isinstance(current_var, set):
            new_value = current_var.copy()
            new_value.update(values)
        elif isinstance(current_var, tuple):
            new_value = list(current_var.copy())
            new_value.extend(values)
            new_value = tuple(new_value)
        else:
            raise TypeError(f"Cannot add to {current_var}")
        return self(new_value)


if __name__ == "__main__":
    number = ContextManagedVar("number", 42)
    assert number.get() == 42
    with number(43):
        assert number.get() == 43
        with number(44):
            assert number.get() == 44
        assert number.get() == 43
    assert number.get() == 42

    lst = ContextManagedVar("lst", ["abc"])
    assert lst.get() == ["abc"]
    with lst(["def"]):
        assert lst.get() == ["def"]
        with lst.add("ghi"):
            assert lst.get() == ["def", "ghi"]
        assert lst.get() == ["def"]
    assert lst.get() == ["abc"]
    print("ContextManagedVar passed")
