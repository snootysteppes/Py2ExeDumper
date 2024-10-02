import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import argparse
import imp
import marshal
import os
import struct
import sys
import time
import pefile
import uncompyle6

IGNORE = [
    '<install zipextimporter>.pyc',  # zip importer added by py2exe
]

def __timestamp():
    """Generate timestamp data for pyc header."""
    today = time.time()
    return struct.pack('=L', int(today))

def __build_magic(magic):
    """Build Python magic number for pyc header."""
    return struct.pack('Hcc', magic, b'\r', b'\n')

def __current_magic():
    """Return the current Python magic number."""
    return imp.get_magic()

# Dictionary of Python versions and their magic numbers
versions = {
    '1.5': __build_magic(20121),
    '1.6': __build_magic(50428),
    '2.0': __build_magic(50823),
    '2.1': __build_magic(60202),
    '2.2': __build_magic(60717),
    '2.3': __build_magic(62011),
    '2.4': __build_magic(62061),
    '2.5': __build_magic(62131),
    '2.6': __build_magic(62161),
    '2.7': __build_magic(62191),
}

def get_scripts_resource(pe):
    """Return the PYTHONSCRIPT resource entry from the PE file."""
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.name and entry.name.string == u"PYTHONSCRIPT":
            return entry.directory.entries[0].directory.entries[0]
    raise ValueError("PYTHONSCRIPT resource not found in the PE file.")

def resource_dump(pe, res):
    """Return the dump of the given resource from the PE file."""
    rva = res.data.struct.OffsetToData
    size = res.data.struct.Size
    return pe.get_data(rva, size)

def get_co_from_dump(data):
    """Return the code objects from the resource dump."""
    current = struct.calcsize('iiii')
    metadata = struct.unpack('iiii', data[:current])

    print(f"Magic value: {metadata[0]:x}")
    print(f"Code bytes length: {metadata[3]}")

    # Extract archive name
    arcname = bytearray()
    while data[current] != 0:
        arcname.append(data[current])
        current += 1
    arcname = arcname.decode('utf-8')
    print(f"Archive name: {arcname or '-'}")

    code_bytes = data[current + 1:-2]
    # Validate code bytes length
    if len(code_bytes) != metadata[3]:
        raise ValueError("Mismatch in code bytes length.")

    return marshal.loads(code_bytes)

def save_co_to_pyc(co, version, output_dir):
    """Save the code object as a pyc file."""
    pyc_header = version + __timestamp()
    pyc_basename = os.path.basename(co.co_filename)
    pyc_name = f"{pyc_basename}.pyc"

    if pyc_name not in IGNORE:
        print(f"Extracting {pyc_name}")
        destination = os.path.join(output_dir, pyc_name)
        with open(destination, 'wb') as pyc_file:
            pyc_file.write(pyc_header)
            marshaled_code = marshal.dumps(co)
            pyc_file.write(marshaled_code)
        return destination  # return the filename of the saved .pyc file

def decompile_pyc(pyc_filename, output_dir):
    """Decompile the pyc file to Python source code."""
    py_filename = pyc_filename[:-1]  # remove the 'c' from '.pyc'
    with open(py_filename, 'w') as py_file:
        uncompyle6.decompile_file(pyc_filename, py_file)

def unpy2exe(filename, python_version=None, output_dir=None, decompile=False, progress_bar=None):
    """Extract and optionally decompile py2exe-packed Python scripts."""
    try:
        # Set the Python version magic number
        version = versions.get(python_version, __current_magic())

        # Set the output directory
        if output_dir is None:
            output_dir = '.'
        elif not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Load the PE file and extract Python scripts
        pe = pefile.PE(filename)
        script_res = get_scripts_resource(pe)
        dump = resource_dump(pe, script_res)
        code_objects = get_co_from_dump(dump)

        # Update progress bar
        total = len(code_objects)
        step = 0

        # Save the extracted code objects and optionally decompile them
        for co in code_objects:
            pyc_filename = save_co_to_pyc(co, version, output_dir)
            if decompile:
                decompile_pyc(pyc_filename, output_dir)

            # Update progress
            step += 1
            if progress_bar:
                progress_bar["value"] = (step / total) * 100
                root.update_idletasks()

        messagebox.showinfo("Success", "Extraction completed successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

def browse_file():
    """Open a file dialog to browse for an executable file."""
    filename = filedialog.askopenfilename(filetypes=[("Executable files", "*.exe")])
    if filename:
        output_dir = filedialog.askdirectory(title="Select Output Directory")
        if output_dir:
            version = version_combobox.get()
            unpy2exe(filename, python_version=version, output_dir=output_dir, decompile=decompile_var.get(), progress_bar=progress)

# Set up the GUI using Tkinter
root = tk.Tk()
root.title("py2exe | @snootysteppes")

frame = tk.Frame(root)
frame.pack(padx=20, pady=20)

button = tk.Button(frame, text="Browse files", command=browse_file)
button.grid(row=0, column=0, padx=10, pady=10)

# Version selector
tk.Label(frame, text="Python Version:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
version_combobox = ttk.Combobox(frame, values=list(versions.keys()), state="readonly")
version_combobox.set('2.7')  # Set default version
version_combobox.grid(row=1, column=1, padx=10, pady=10)

# Decompile option
decompile_var = tk.BooleanVar()
decompile_check = tk.Checkbutton(frame, text="Decompile", variable=decompile_var)
decompile_check.grid(row=2, column=0, padx=10, pady=10)

# Progress bar
progress = ttk.Progressbar(frame, orient="horizontal", length=200, mode="determinate")
progress.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

# Start the GUI main loop
root.mainloop()
