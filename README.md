# Overview

`luau-analysis` is a Rust utility to help extract details from memory (e.g. `.dmp`) files.  Thus far information collected from these files includes:
1. Potential pointers to data
2. Downloaded Roblox Assets

The type of dump file is actually irrelevant as long as there is information annotating the physical memory information (e.g. offsets in the file), 
sections (or file names), and the virtual address where the data is loaded in the process.  For simplicity, `radare2` is used for extracting this 
information from dump files.  The utility uses this information to detect potential memory pointers to data structures.

In the current form, the utility provides the following metadata:
1. Pointers (e.g. source address --> sink address --> sink value)
2. Search results for downloaded Roblox assets found using regular expressions.  The dump file is scanned with and without the dump metadata, which
yields different results.


# Requirements
There are three prerequisites to using this tool:
1. Radare2, Rust and git, (gcc, libsqlite3-dev libpq-dev libmysqlclient-dev (for `diesel`)) are installed
 * Install Misc: `sudo apt install make cmake git gcc libsqlite3-dev libpq-dev libmysqlclient-dev`
 * Install Radare: `git clone https://github.com/radareorg/radare2; cd radare2; ./sys/install.sh`
 * Install Rust: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
2. A Memory dump that can be analyzed using Radare2
 * full memory `dmp` file from a process using Windows Task Manager or SysInternals Process Explorer 
3. Compiled version of this program (e.g. `cargo build`) 
4. Radare sections from the dump file (`r2 -qc 'iSj' [PATH_TO_DUMP]`)

# setup
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
git clone https://github.com/trumetaverse/luau-analysis
cd luau-analysis/luau-sifter/
cargo build
./target/debug/luau-sifter --dmp [PATH_TO_DUMP] --r2_sections [PATH_TO_SECTIONS.json] \
--output_path [directory where results will be]
```

The output can be fed into other tools to help facilitate more direct analysis.
