from argparse import ArgumentParser
from datetime import datetime
from ipaddress import IPv4Address, AddressValueError
from os import listdir, path
from pathlib import Path
from re import findall, match
import sys


def scrape_logs_for_ip(logfiles, ip_address):
    """
    Function that finds the path of a given IPv4 address across N devices,
    given N device log files. Assumes that lines in log files follow the strict
    format: [device][date time][free form text with or without IPv4 address].
    The path of the ip address across devices is output in order of oldest
    log to newest.

    Parameters
    ----------
    logfiles: list(str)
        A list of paths to device log files
    ip_address: str
        String containing a valid IP address

    Returns
    ----------
    output_msg: str
        Formatted string containing the path of the specified IPv4 address
        across devices (if any).

    Raises
    ----------
    ValueError: If the format of any line in the logs has an obviously invalid
        format
    """
    logs_with_ip = list()
    # Regex for matching log lines in the format [device][date time][text]
    log_line_regex = "^\[(.*)\]\[(.*)\]\[(.*)\]$"
    # Regex for finding IPv4-lookalike strings in the text. This is a very
    # lenient regex, and the logic using it should impose more stringent checks
    # if IPv4 filtering is required
    ip_lookalike_regex = "((?:\d*\.)+\d+\.?)"

    for path_to_logfile in logfiles:
        # Open the file and read all lines
        with open(path_to_logfile) as device_log:
            lines = device_log.readlines()

        for line_idx, line in enumerate(lines):
            # Segregate contents of each line based on expected line format
            capture_groups = findall(log_line_regex, line)
            # Ensure correct line format
            if (len(capture_groups) != 1) or (len(capture_groups[0]) != 3):
                raise ValueError(
                    "Line {} ({}) in {} has an illegal format"
                    .format(line_idx, line, path_to_logfile)
                )
            [device_id, timestamp, text] = capture_groups[0]
            # Store only the interesting log lines for further processing
            all_possible_matches = findall(ip_lookalike_regex, text)
            # Explicitly check for exact matches among possible ones
            if ip_address in all_possible_matches:
                logs_with_ip.append("[{}][{}]".format(timestamp, device_id))

    # Create output response depending on results
    if len(logs_with_ip) == 0:
        output_msg = (
            "The IPv4 address {} does not exist in the given log files"
            .format(ip_address)
        )
    else:
        # Sort all extracted logs by timestamp, with the assumption that the
        # the format is <%Y/%m/%d %H:%M:%S> as given in the problem statement
        sorted_ip_logs = sorted(
            logs_with_ip,
            key=lambda line_in_path: datetime.strptime(
                line_in_path[1:].split(']')[0],
                '%Y/%m/%d %H:%M:%S'
            )
        )
        # Finally, concat all lines in the sorted list of relevant logs into
        # a single string with proper formatting
        output_msg = (
            "Path for IPv4 address {} =\n{}"
            .format(ip_address, '\n'.join(sorted_ip_logs))
        )
    return output_msg


def check_input_sanity(args):
    """
    Helper function that takes parsed input and ensures that it is valid.

    Parameters
    ----------
    args: dict
        Dictionary containing the arguments passed in to the script from the
        command line.

    Returns
    ----------
    error_msg: list(str)
        A list of errors (if any) encountered among the input parameters
    """
    error_msg = list()
    # Ensure that provided files or directory is valid
    if (args['directory']) and (args['files']):
        error_msg.append('Must either provide a directory or 1 or more log '
                         'files, but not both.')
    if not (args['directory'] or args['files']):
        error_msg.append('Must either provide a directory or 1 or more log '
                         'files, but not neither.')
    if args['directory']:
        if not (Path(args['directory']).is_dir()):
            error_msg.append('Provided directory is not actually a directory')
        if not (listdir(args['directory'])):
            error_msg.append('Provided directory does not contain any logs')
    if args['files']:
        if not all(Path(path).is_file() for path in args['files']):
            error_msg.append(
                'At least one provided file is not actually a file'
            )
    # Ensure that provided ip address is valid
    try:
        IPv4Address(args['ip_address'])
    except AddressValueError:
        error_msg.append('The provided IPv4 address must be valid.')
    return error_msg


if __name__ == "__main__":
    # Provide command line interface
    parser = ArgumentParser(
        description='Script for finding the path of an IPv4 address across N '
                    'devices using the log files from each device'
    )
    parser.add_argument(
        '-i',
        '--ip_address',
        help='IPv4 address to search for in provided log files'
    )
    parser.add_argument(
        '-f',
        '--files',
        help='Device log files in which to search for the given IPv4 address. '
             'WARNING: You can either provide 1 or more files here, or a '
             'directory with the `-d` flag, but not both',
        nargs="+"  # can provide 0 or more files
    )
    parser.add_argument(
        '-d',
        '--directory',
        help='Folder that contains only valid log files. If a folder is '
             'provided, all the files it contains will be treated as relevant '
             'log files. WARNING: You can either provide a directory here, or '
             '1 or more log files with the `-f` flag, but not both'
    )
    parsed_args = vars(parser.parse_args())
    errors_found = (check_input_sanity(parsed_args))
    if len(errors_found) > 0:
        print("The inputs to the script are not valid. Please check them "
              "and try again. The following errors were encountered: \n>> {}\n"
              .format('\n>> '.join(errors_found)))
        parser.print_usage()  # Remind user of script usage rules
        sys.exit(1)  # Exit with non-zero value (which indicates errors found)

    # Compile list of all files from the provided inputs
    files = (
        parsed_args['files'] or
        [path.join(parsed_args['directory'], file)
         for file in listdir(parsed_args['directory'])]
    )

    # Finally, scrape logs and print results to stdout
    try:
        print(scrape_logs_for_ip(files, parsed_args['ip_address']))
    except ValueError as e:
        print("An error was encountered during the ip address scraping process:"
              "\n>> {}\n".format(e.__str__()))
        parser.print_usage()  # Remind user of script usage rules
        sys.exit(1)  # Exit with error signifier
