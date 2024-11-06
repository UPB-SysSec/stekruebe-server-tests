def yield_tuple(func):
    def wrapper(*args, **kwargs):
        return tuple(func(*args, **kwargs))

    return wrapper


def yield_list(func):
    def wrapper(*args, **kwargs):
        return list(func(*args, **kwargs))

    return wrapper


def yield_dict(func):
    def wrapper(*args, **kwargs):
        return dict(func(*args, **kwargs))

    return wrapper


if __name__ == "__main__":
    # self test
    @yield_list
    def foo():
        yield 1
        yield 2

    assert foo() == [1, 2]

    @yield_dict
    def bar():
        yield "a", 1
        yield "b", 2

    assert bar() == {"a": 1, "b": 2}
    print("yield_wrapper.py: self test passed")
