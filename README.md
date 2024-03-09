# Py2ExeDumper

## What is this?

Py2ExeDumper is a Python-based tool designed to extract Python bytecode (`.pyc` files) from a `py2exe` executable and optionally decompile the extracted `.pyc` files into Python source code. This document provides a comprehensive, complex, and slightly over-explained guide to understanding and using Py2ExeDumper.

## Dependencies

Py2ExeDumper relies on the following Python libraries:

- `tkinter`: Used for creating the graphical user interface (GUI).
- `pefile`: Used for parsing the `py2exe` executable.
- `uncompyle6`: Used for decompiling `.pyc` files into Python source code.

These dependencies can be installed using pip:

```bash
pip install tkinter pefile uncompyle6
```

## Code Overview

The Py2ExeDumper script is divided into several sections, each responsible for a specific part of the extraction and decompilation process.

### Helper Functions

Several helper functions are defined at the beginning of the script:

- `__timestamp()`: Generates timestamp data for the `.pyc` header.
- `__build_magic(magic)`: Builds the Python magic number for the `.pyc` header.
- `__current_magic()`: Returns the current Python magic number.

These functions are used internally by Py2ExeDumper to create the `.pyc` files.

### Main Functions

The main functions of Py2ExeDumper are:

- `get_scripts_resource(pe)`: Returns the PYTHONSCRIPT resource entry from the `py2exe` executable.
- `resource_dump(pe, res)`: Returns the dump of the given resource.
- `get_co_from_dump(data)`: Returns the code objects from the dump.
- `save_co_to_pyc(co, version, output_dir)`: Saves the code object as a `.pyc` file.
- `decompile_pyc(pyc_filename, output_dir)`: Decompiles a `.pyc` file into Python source code.
- `unpy2exe(filename, python_version=None, output_dir=None, decompile=False)`: The main function that orchestrates the extraction and optional decompilation process.

### GUI

The GUI is created using `tkinter`. It consists of a single window with a "Browse" button. When this button is clicked, a file dialog opens, allowing the user to select the `py2exe` executable. The selected file is then passed to the `unpy2exe` function.

## Usage

To use Py2ExeDumper, run the script and click the "Browse" button in the GUI. Select the `py2exe` executable from which you want to extract `.pyc` files. If the extraction is successful, a success message is displayed. If an error occurs during the extraction, an error message is displayed.

By default, Py2ExeDumper will also decompile the extracted `.pyc` files into Python source code. This behavior can be changed by modifying the `decompile` argument in the `unpy2exe` function call in the `browse_file` function.

## Disclaimer & Credits
Please note that Py2ExeDumper should be used responsibly and in accordance with all applicable laws and regulations. Decompiling software may infringe on the software's license agreement and/or copyright laws, so always ensure you have the necessary permissions before using Py2ExeDumper. 
https://github.com/4w4k3/rePy2exe for some of the logic.
