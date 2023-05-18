import os
import shlex
import sys
import json
import argparse
import subprocess
import logging

LOGGING_FORMAT = '[%(asctime)s - %(name)s] %(message)s'
LOGGER_NAME = "analyze_roblox_dumps"
LOGGER = logging.getLogger(LOGGER_NAME)

LOG_FILE = 'analyze_roblox_dumps.log'

def init_logger(name=LOGGER_NAME,
                log_level=logging.DEBUG,
                logging_fmt=LOGGING_FORMAT,
                log_file=LOG_FILE):
    global LOGGER
    logging.getLogger(name).setLevel(log_level)
    formatter = logging.Formatter(logging_fmt)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(log_level)
    ch.setFormatter(formatter)
    logging.getLogger(name).addHandler(ch)
    fh = logging.FileHandler(log_file)
    fh.setFormatter(formatter)
    fh.setLevel(log_level)
    logging.getLogger(name).addHandler(fh)
    LOGGER = logging.getLogger(name)
    return logging.getLogger(name)

R2_COMMAND_FMT = 'r2 -qc iSj "{dump_file_path}"'

SIFTER_BIN = '../luau-sifter/target/debug/luau-sifter'
BASE_ANALYSIS_DIR = './'
DUMP_FMT = "{bins_dir}/{bin_name}.{dmp_ext}"
OUTPUT_FMT = "{searches_dir}/{bin_name}/"
RADARE_MEM_MAP_FMT = "{mems_dir}/{bin_name}.json"

BINS_DIR = os.path.join(BASE_ANALYSIS_DIR, 'bins')
MEMS_DIR = os.path.join(BASE_ANALYSIS_DIR, 'mem')
SEARCHES_DIR = os.path.join(BASE_ANALYSIS_DIR, 'searches')
DUMP_EXT = 'DMP'

SIFTER_COMMAND_FMT = '"{sifter_command}" -n {num_threads} -plr -o "{output_dir}" ' + \
                 '--r2-sections "{mem_file}" --dmp "{dmp_file}"'

def create_sifter_command(num_threads, bin_name):
    dmp_file = DUMP_FMT.format(**{"bins_dir": BINS_DIR, 'bin_name': bin_name, "dmp_ext": DUMP_EXT})
    mems_file = RADARE_MEM_MAP_FMT.format(**{'mems_dir': MEMS_DIR, 'bin_name': bin_name})
    output_dir = OUTPUT_FMT.format(**{"searches_dir": SEARCHES_DIR, "bin_name": bin_name})
    os.makedirs(output_dir, exist_ok=True)
    cmd = SIFTER_COMMAND_FMT.format(**{'sifter_command': SIFTER_BIN,
                                       'num_threads': num_threads,
                                       'output_dir': output_dir,
                                       'mem_file': mems_file,
                                       'dmp_file': dmp_file})
    return cmd



def reset_global_deps(base_dir, sifter_bin):
    global BASE_ANALYSIS_DIR, BINS_DIR, MEMS_DIR, SEARCHES_DIR, SIFTER_BIN
    BASE_ANALYSIS_DIR = base_dir
    BINS_DIR = os.path.join(BASE_ANALYSIS_DIR, 'bins')
    MEMS_DIR = os.path.join(BASE_ANALYSIS_DIR, 'mem')
    SEARCHES_DIR = os.path.join(BASE_ANALYSIS_DIR, 'searches')
    SIFTER_BIN = sifter_bin

def create_output_structure(base_dir=None):
    global BASE_ANALYSIS_DIR
    base_dir = base_dir if isinstance(base_dir, str) else BASE_ANALYSIS_DIR
    reset_global_deps(base_dir)
    # create bins
    os.makedirs(BINS_DIR, exist_ok=True)
    # create mems
    os.makedirs(MEMS_DIR, exist_ok=True)
    # create searches
    os.makedirs(SEARCHES_DIR, exist_ok=True)

def get_dump_file_path(bin_name, ext='DMP'):
    global DUMP_FMT, BASE_ANALYSIS_DIR, BINS_DIR
    if bin_name.find('.' + ext) > 0 and os.path.splitext(bin_name)[1].lower() == ext:
        return os.path.join(BINS_DIR, bin_name)
    return DUMP_FMT.format(**{'bins_dir': BINS_DIR, 'bin_name': bin_name, 'dmp_ext': ext}).replace('//', '/')

def execute_radare_command(dmp_file_path=None, bin_name=None, ext='DMP'):
    dump_file_path = dmp_file_path
    if bin_name is not None:
        dump_file_path = get_dump_file_path(bin_name, ext)

    if dump_file_path is None:
        raise Exception("Missing valid 'bin_name' or path to memory dump")

    cmd = R2_COMMAND_FMT.format(**{'dump_file_path':dump_file_path})
    process = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = b''
    while True:
        if process.returncode is not None:
            break
        stdout, stderr = process.communicate()
        output = output + stdout
    return output

def execute_lua_sifter(base_dir, sifter_bin, bin_name, num_threads):
    reset_global_deps(base_dir, sifter_bin)
    cmd = create_sifter_command(num_threads, bin_name)
    process = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = b''
    while True:
        if process.returncode is not None:
            break
        stdout, stderr = process.communicate()
        output = output + stdout
    return output

def write_radare_output(bin_name, output):
    output_file = RADARE_MEM_MAP_FMT.format(**{'mems_dir': MEMS_DIR, 'bin_name': bin_name})
    LOGGER.info("Writing radare results ({}) to  {}".format(len(output), output_file))
    open(output_file, 'w').write(output)

def perform_radare_analysis(bin_name):
    LOGGER.info("Extracting memory sections from {}".format(bin_name))
    output = execute_radare_command(bin_name=bin_name)
    try:
        results = json.loads(output)
        write_radare_output(bin_name, json.dumps(results))
        LOGGER.info("Done extracting memory sections from {}".format(bin_name))
    except:
        # raise Exception("Failed to process: {}".format(bin_name))
        LOGGER.info("Failed extracting memory sections from {}".format(bin_name))
        raise
    return results

def perform_luau_analysis(base_dir, sifter_bin, bin_name, num_threads):
    LOGGER.info("Sifting through {} for pointers, lua_Page, and regex".format(bin_name))
    output = execute_lua_sifter(base_dir, sifter_bin, bin_name, num_threads)
    LOGGER.info("Done sifting through {} for pointers, lua_Page, and regex".format(bin_name))
    return output


parser = argparse.ArgumentParser(
    prog='analyze_rbx_memory',
    description='extract identify and extract relevant objects from a Roblox memory dump')

parser.add_argument('-c', '--create-output-structure', help='create standard output structure based on base',
                    action="store_true", default=False)
parser.add_argument('-radare', help='perform radare2 analysis', action="store_true", default=False)
parser.add_argument('-sifter', help='perform sifter analysis', action="store_true", default=False)
parser.add_argument('-luau_sifter_bin', help='path to luau-sifter bin', type=str, default=SIFTER_BIN)
parser.add_argument('-base_dir', help='base directory for analysis', type=str, required=True)
parser.add_argument('-bin_name', help='dump name to analyze', type=str, required=True)

parser.add_argument('-num_threads', help='number of concurrent processes', type=int, default=3030)
parser.add_argument('-dmp_ext', help='extension of the dump file', type=str, default=DUMP_EXT)


if __name__ == "__main__":
    init_logger()
    args = parser.parse_args()
    args_dict = vars(args)
    base_dir = args_dict['base_dir']
    sifter_bin = args_dict['luau_sifter_bin']
    bin_name = args_dict['bin_name']
    num_threads = args_dict['num_threads']

    reset_global_deps(base_dir, sifter_bin)
    if args_dict.get('radare', False):
        perform_radare_analysis(bin_name)

    if args_dict.get('sifter', False):
        perform_luau_analysis(base_dir, sifter_bin, bin_name,num_threads)


