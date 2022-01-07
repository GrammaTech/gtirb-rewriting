# Command Line Drivers

gtirb-rewriting provides a command line tool, called gtirb-rewriting, that
can run passes on an IR file and write out a new IR file. The passes to run
are specified through the --run option and executed on the IR in the order
they are specified.

For example, to run the stack-stamp pass (assuming gtirb-stack-stamp is
installed):
```shell
gtirb-rewriting --run stack-stamp input.gtirb output.gtirb
```

## Discovery

The gtirb-rewriting command line tool discovers passes and pass drivers
using [setuptools entry points](https://setuptools.pypa.io/en/latest/userguide/entry_point.html#dynamic-discovery-of-services-and-plugins).
Each Python package that implements a gtirb-rewriting pass should expose it as
a gtirb_rewriting entrypoint.

For example:
```python
# in setup.py
setup(
    ...,
    entry_points={
        "gtirb_rewriting": [
            # my_module is the Python module name and MyPass is the name of
            # the pass class within it.
            "my-pass=my_module:MyPass"
        ]
    }
)
```

## Passes and Pass Drivers

If the pass class can be instantiated without arguments, the pass class can
be exposed directly as the entry point. However, if the pass requires
arguments to initialize a pass driver will be required.

Pass drivers can add options to its [argparse group](https://docs.python.org/3/library/argparse.html#argument-groups)
by implementing the `add_options` method. Then in its `create_pass` method it
can access the arguments namespace to be able to instantiate the Pass class.

For example
```python
class MyPass(Pass):
    def __init__(self, message):
        pass

class MyPassDriver(PassDriver):
    def add_options(self, group):
        group.add_argument("--my-pass-message", required=True)

    def create_pass(self, args, ir):
        return MyPass(args.message)

    def description(self):
        return "My pass does something"
```

Option names should be unique across passes, so consider names like
`--my-pass-message` instead of just `--message`.

## Extra Libraries

Transforms can introduce dependencies on shared libraries that must be present
at run-time for the reassembled binary. Pass drivers can expose this
information by implementing the `extra_libraries` method and users can
retrieve the libraries with the `--extra-libs` command line option.

## Pass-specific Drivers

Most gtirb-rewriting-based transforms also expose their passes through a
standalone command line tool. gtirb-rewriting helps with this by providing a
standard main function:
```python
# in __main__.py
import gtirb_rewriting.driver

def main():
    # my-pass was previously registered in setup.py
    gtirb_rewriting.driver.main("my-pass")

if __name__ == "__main__":
    main()
```

For simple command line scripts that are not distributed as a package, the
`gtirb_rewriting.driver.main` function can be directly passed a `Pass` or
`PassDriver` class to use.
