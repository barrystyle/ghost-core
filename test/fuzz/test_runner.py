#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run fuzz test targets.
"""

import argparse
import configparser
import os
import sys
import subprocess
import logging

# Fuzzers known to lack a seed corpus in https://github.com/bitcoin-core/qa-assets/tree/master/fuzz_seed_corpus
FUZZERS_MISSING_CORPORA = [
    "addr_info_deserialize",
    "base_encode_decode",
    "block",
    "block_file_info_deserialize",
    "block_filter_deserialize",
    "block_header_and_short_txids_deserialize",
    "decode_tx",
    "fee_rate_deserialize",
    "flat_file_pos_deserialize",
    "hex",
    "integer",
    "key_origin_info_deserialize",
    "merkle_block_deserialize",
    "out_point_deserialize",
    "parse_hd_keypath",
    "parse_numbers",
    "parse_script",
    "parse_univalue",
    "partial_merkle_tree_deserialize",
    "partially_signed_transaction_deserialize",
    "prefilled_transaction_deserialize",
    "psbt_input_deserialize",
    "psbt_output_deserialize",
    "pub_key_deserialize",
    "script_deserialize",
    "sub_net_deserialize",
    "tx_in",
    "tx_in_deserialize",
    "tx_out",
]

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        "-l",
        "--loglevel",
        dest="loglevel",
        default="INFO",
        help="log events at this level and higher to the console. Can be set to DEBUG, INFO, WARNING, ERROR or CRITICAL. Passing --loglevel DEBUG will output all logs to console.",
    )
    parser.add_argument(
        '--export_coverage',
        action='store_true',
        help='If true, export coverage information to files in the seed corpus',
    )
    parser.add_argument(
        'seed_dir',
        help='The seed corpus to run on (must contain subfolders for each fuzz target).',
    )
    parser.add_argument(
        'target',
        nargs='*',
        help='The target(s) to run. Default is to run all targets.',
    )

    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(
        format='%(message)s',
        level=int(args.loglevel) if args.loglevel.isdigit() else args.loglevel.upper(),
    )

    # Read config generated by configure.
    config = configparser.ConfigParser()
    configfile = os.path.abspath(os.path.dirname(__file__)) + "/../config.ini"
    config.read_file(open(configfile, encoding="utf8"))

    if not config["components"].getboolean("ENABLE_FUZZ"):
        logging.error("Must have fuzz targets built")
        sys.exit(1)

    # Build list of tests
    test_list_all = parse_test_list(makefile=os.path.join(config["environment"]["SRCDIR"], 'src', 'Makefile.test.include'))

    if not test_list_all:
        logging.error("No fuzz targets found")
        sys.exit(1)

    logging.info("Fuzz targets found: {}".format(test_list_all))

    args.target = args.target or test_list_all  # By default run all
    test_list_error = list(set(args.target).difference(set(test_list_all)))
    if test_list_error:
        logging.error("Unknown fuzz targets selected: {}".format(test_list_error))
    test_list_selection = list(set(test_list_all).intersection(set(args.target)))
    if not test_list_selection:
        logging.error("No fuzz targets selected")
    logging.info("Fuzz targets selected: {}".format(test_list_selection))

    try:
        help_output = subprocess.run(
            args=[
                os.path.join(config["environment"]["BUILDDIR"], 'src', 'test', 'fuzz', test_list_selection[0]),
                '-help=1',
            ],
            timeout=10,
            check=True,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        ).stderr
        if "libFuzzer" not in help_output:
            logging.error("Must be built with libFuzzer")
            sys.exit(1)
    except subprocess.TimeoutExpired:
        logging.error("subprocess timed out: Currently only libFuzzer is supported")
        sys.exit(1)

    run_once(
        corpus=args.seed_dir,
        test_list=test_list_selection,
        build_dir=config["environment"]["BUILDDIR"],
        export_coverage=args.export_coverage,
    )


def run_once(*, corpus, test_list, build_dir, export_coverage):
    for t in test_list:
        corpus_path = os.path.join(corpus, t)
        if t in FUZZERS_MISSING_CORPORA:
            os.makedirs(corpus_path, exist_ok=True)
        args = [
            os.path.join(build_dir, 'src', 'test', 'fuzz', t),
            '-runs=1',
            '-detect_leaks=0',
            corpus_path,
        ]
        logging.debug('Run {} with args {}'.format(t, args))
        result = subprocess.run(args, stderr=subprocess.PIPE, universal_newlines=True)
        output = result.stderr
        logging.debug('Output: {}'.format(output))
        result.check_returncode()
        if not export_coverage:
            continue
        for l in output.splitlines():
            if 'INITED' in l:
                with open(os.path.join(corpus, t + '_coverage'), 'w', encoding='utf-8') as cov_file:
                    cov_file.write(l)
                    break


def parse_test_list(makefile):
    with open(makefile, encoding='utf-8') as makefile_test:
        test_list_all = []
        read_targets = False
        for line in makefile_test.readlines():
            line = line.strip().replace('test/fuzz/', '').replace(' \\', '')
            if read_targets:
                if not line:
                    break
                test_list_all.append(line)
                continue

            if line == 'FUZZ_TARGETS =':
                read_targets = True
    return test_list_all


if __name__ == '__main__':
    main()
