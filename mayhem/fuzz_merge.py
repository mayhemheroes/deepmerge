#!/usr/bin/python3
import timeit
import atheris
import logging
import sys
import pprint

pp = pprint.PrettyPrinter(indent=4)

with atheris.instrument_imports():
    import deepmerge
    import deepmerge.exception
# No logging
logging.disable(logging.CRITICAL)


# @atheris.instrument_func
def _get_fuzzed_object(fdp: atheris.FuzzedDataProvider, base_name: str, depth: int = 0) -> dict:
    fuzzed_object = {}
    elem_count = fdp.ConsumeIntInRange(1, 5)
    try:
        for i in range(elem_count):
            # Decide if we want to add a list, dict, or concrete value
            new_val_type = fdp.ConsumeIntInRange(0, 2)

            # To avoid a maximum recursion error, we limit the depth of the fuzzed object
            if depth > 60:
                new_val_type = 2 # Force a concrete value

            if new_val_type == 0:
                # Add a new object
                key_ty = "obj"
                new_val = _get_fuzzed_object(fdp, base_name, depth + 1)
            elif new_val_type == 1:
                pass
                # Add a list
                key_ty = "list"
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

            # Add the new value to the object
            key = f"{base_name}_{key_ty}_{depth}_{i}"
            fuzzed_object[key] = new_val
        return fuzzed_object
    except RecursionError:
        return fuzzed_object


@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        # Get two fuzzer python objects
        base = _get_fuzzed_object(fdp, 'a')
        next = _get_fuzzed_object(fdp, 'b')

        result = deepmerge.always_merger.merge(base, next)
        repr(result)
    except deepmerge.exception.DeepMergeException as e:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
    # with open('/dev/urandom', 'rb') as f:
    #     for _ in range(300):
    #         data = f.read(50000)
    #         fdp = atheris.FuzzedDataProvider(data)
    #         begin = timeit.default_timer()
    #         val = _get_fuzzed_object(fdp, 'val')
    #         end = timeit.default_timer()
    #         print(f"Time: {end - begin}")


if __name__ == "__main__":
    main()
