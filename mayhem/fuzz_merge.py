#!/usr/bin/python3
import atheris
import logging
import sys
with atheris.instrument_imports():
    import deepmerge
    import deepmerge.exception
    import deepmerge.strategy

# No logging
logging.disable(logging.CRITICAL)


@atheris.instrument_func
def _shuffle_list(l: list, fdp):
    import random
    """Shuffles a list in place using indices from fdp"""
    for i in reversed(range(1, len(l))):
        random.shuffle(l, )
        j = fdp.ConsumeIntInRange(0, i)
        l[i], l[j] = l[j], l[i]


@atheris.instrument_func
def _get_fuzzed_object(fdp: atheris.FuzzedDataProvider, base_name: str, depth: int = 0) -> dict:
    # Determine if root element should be a list, dict, or set
    root_ty = fdp.ConsumeIntInRange(0, 2)
    if root_ty == 0:
        root = {}
    elif root_ty == 1:
        root = []
    else:
        root = set()

    elem_count = fdp.ConsumeIntInRange(0, 5)
    try:
        for i in range(elem_count):
            # Decide if we want to add a list, dict, frozenset, or concrete value
            new_val_type = fdp.ConsumeIntInRange(0, 2)

            # To avoid a maximum recursion error, we limit the depth of the fuzzed object
            if depth > 60 or isinstance(root, set):
                new_val_type = 3  # Force a concrete value

            if new_val_type == 0:
                # Add a new object
                key_ty = "obj"
                new_val = _get_fuzzed_object(fdp, base_name, depth + 1)
            elif new_val_type == 1:
                # Add a list
                key_ty = "list"
                new_val = []
                for _ in range(fdp.ConsumeIntInRange(0, 2)):
                    new_val.append(_get_fuzzed_object(fdp, base_name, depth + 1))
                if isinstance(root, set):
                    new_val = tuple(new_val)  # List is not hashable, so we convert it to a tuple
            elif new_val_type == 2:
                # Add a frozenset
                key_ty = "set"
                new_val = []
                for _ in range(fdp.ConsumeIntInRange(0, 2)):
                    new_val.append(_get_fuzzed_object(fdp, base_name, depth + 1))
            else:
                concrete_ty = fdp.ConsumeIntInRange(0, 5)
                key_ty = "conc"
                if concrete_ty == 0:
                    new_val = fdp.ConsumeInt(8)
                elif concrete_ty == 1:
                    new_val = fdp.ConsumeFloat()
                elif concrete_ty == 2:
                    new_val = fdp.ConsumeBool()
                elif concrete_ty == 3:
                    new_val = fdp.ConsumeUnicode(15)
                else:
                    new_val = fdp.ConsumeBytes(15)

            if isinstance(root, dict):
                key = f"{base_name}_{key_ty}_{depth}_{i}"
                root[key] = new_val
            elif isinstance(root, list):
                root.append(new_val)
            elif isinstance(root, set):
                root.add(new_val)
        return root
    except RecursionError:
        return root


@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        # Get two fuzzer python objects
        base = _get_fuzzed_object(fdp, 'a')
        next = _get_fuzzed_object(fdp, 'b')

        # Attempt basic merger
        result = deepmerge.always_merger.merge(base, next)

        # Attempt custom merger

        # Shuffle strategies per fuzzer's desire
        dict_strategies = ['merge', 'override']
        list_strategies = ['prepend', 'append', 'append_unique', 'override']
        set_strategies = ['union', 'intersect', 'override']

        _shuffle_list(dict_strategies, fdp)
        _shuffle_list(list_strategies, fdp)
        _shuffle_list(set_strategies, fdp)

        type_strategies = [
            (dict, dict_strategies),
            (list, list_strategies),
            (set, set_strategies),
        ]

        fallback_strategies = ["override", "use_existing"]
        _shuffle_list(fallback_strategies, fdp)

        type_conflict_strategies = ["override", "use_existing", "override_if_not_empty"]
        _shuffle_list(type_conflict_strategies, fdp)
        
        merger = deepmerge.Merger(type_strategies, fallback_strategies, type_conflict_strategies)
        merger.merge(base, next)

    except deepmerge.exception.DeepMergeException as e:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
