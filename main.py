#!/usr/bin/env python3
"""
pa-permission-exfiltration-path-analyzer

Analyzes potential paths to sensitive data based on existing permissions.
Identifies chains of permission grants that could allow unintended access to critical resources.
"""

import argparse
import grp
import logging
import os
import pwd
import sys
from typing import List, Dict, Any, Optional, Set, Tuple

# Optional dependencies (install with pip install pathspec rich)
try:
    import pathspec
    from pathspec.patterns import GitWildMatchPattern
    from rich.console import Console
    from rich.table import Table
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the script.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(
        description="Analyzes potential permission exfiltration paths."
    )
    parser.add_argument(
        "-r",
        "--root-dir",
        type=str,
        default=".",
        help="Root directory to start the analysis from. Defaults to current directory.",
    )
    parser.add_argument(
        "-u",
        "--user",
        type=str,
        required=True,
        help="User to simulate access for.",
    )
    parser.add_argument(
        "-t",
        "--target-file",
        type=str,
        required=True,
        help="Target file or directory to check access to.",
    )
    parser.add_argument(
        "-i",
        "--ignore-patterns",
        type=str,
        nargs="+",
        help="List of glob patterns to ignore (e.g., '*.tmp' '*/temp/*').",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output.",
    )
    parser.add_argument(
        "--check-write",
        action="store_true",
        help="Check for write access instead of read access.",
    )
    return parser


def resolve_user(user: str) -> Optional[Tuple[int, Set[int]]]:
    """
    Resolves a user name to its uid and the set of group ids it belongs
    to (its primary group plus every group that lists it as a member).

    Returns None when the user does not exist.
    """
    try:
        entry = pwd.getpwnam(user)
    except KeyError:
        return None

    group_ids = {entry.pw_gid}
    for group in grp.getgrall():
        if user in group.gr_mem:
            group_ids.add(group.gr_gid)
    return entry.pw_uid, group_ids


def check_permission(filepath: str, user: str, check_write: bool = False) -> bool:
    """
    Checks if the named user has read or write permission on a path, using
    the permission class that applies to that user: the owner bits when
    the user owns the file, the group bits when the user belongs to the
    file's group, and the other bits otherwise. This is a simplified
    implementation: ACLs are not consulted.

    Args:
        filepath (str): The path to the file.
        user (str): The user to check permissions for.
        check_write (bool): If True, check for write access instead of read.

    Returns:
        bool: True if the user has the specified permissions, False otherwise.
    """

    resolved = resolve_user(user)
    if resolved is None:
        logging.error(f"User does not exist: {user}")
        return False
    user_id, group_ids = resolved

    try:
        st = os.stat(filepath)
        mode = st.st_mode

        if user_id == st.st_uid:
            return bool(mode & (0o200 if check_write else 0o400))
        if st.st_gid in group_ids:
            return bool(mode & (0o020 if check_write else 0o040))
        return bool(mode & (0o002 if check_write else 0o004))
    except Exception as e:
        logging.error(f"Error checking permission for {filepath}: {e}")
        return False


def find_potential_paths(
    root_dir: str,
    target_file: str,
    user: str,
    ignore_patterns: List[str] = None,
    check_write: bool = False
) -> List[List[str]]:
    """
    Finds potential paths from the root directory to the target file where the user has access
    at each step of the path.

    Args:
        root_dir (str): The root directory to start the search from.
        target_file (str): The target file to find paths to.
        user (str): The user to check permissions for.
        ignore_patterns (List[str], optional): List of patterns to ignore. Defaults to None.
        check_write (bool): If True, check for write access instead of read.

    Returns:
        List[List[str]]: A list of paths (list of directory names) where the user has access.
    """

    paths: List[List[str]] = []
    ignore_spec = None
    if ignore_patterns:
        ignore_spec = pathspec.PathSpec.from_lines(
            GitWildMatchPattern, ignore_patterns
        )

    def explore_path(current_path: List[str], current_dir: str):
        """Recursive helper function to explore the directory tree."""
        nonlocal paths

        if ignore_spec:
            relative_dir = os.path.relpath(current_dir, root_dir)
            if ignore_spec.match_file(relative_dir) or ignore_spec.match_file(current_dir):
                logging.debug(f"Ignoring directory: {current_dir}")
                return

        if not check_permission(current_dir, user, check_write):
            logging.debug(f"No access to {current_dir} for {user}")
            return

        current_path.append(current_dir)  # Add current directory to the path

        if os.path.abspath(current_dir) == os.path.abspath(target_file):
            # A path is recorded only when the walk reaches the target
            # itself, and the permission check above has just tested the
            # target's own permission for the named user.
            paths.append(current_path.copy())  # Found a path, add it to the results
            current_path.pop() # remove current dir from the path
            return

        if os.path.isdir(current_dir):
            try:
                for entry in os.listdir(current_dir):
                    next_path = os.path.join(current_dir, entry)
                    explore_path(current_path, next_path)
            except PermissionError as e:
                logging.warning(f"Permission error accessing {current_dir}: {e}")
            except Exception as e:
                logging.error(f"Error listing directory {current_dir}: {e}")

        current_path.pop()  # Backtrack: remove current directory before returning

    explore_path([], root_dir)
    return paths


def main():
    """
    Main function to parse arguments, find paths, and display results.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    root_dir = args.root_dir
    target_file = args.target_file
    user = args.user
    ignore_patterns = args.ignore_patterns
    check_write = args.check_write

    # Input validation
    if not os.path.exists(root_dir):
        logging.error(f"Root directory '{root_dir}' does not exist.")
        sys.exit(1)

    if resolve_user(user) is None:
        logging.error(f"User '{user}' does not exist. No analysis was run.")
        sys.exit(1)

    if not os.path.exists(target_file):
        logging.error(f"Target file '{target_file}' does not exist. No analysis was run.")
        sys.exit(1)

    logging.info(f"Starting permission path analysis for user '{user}'...")
    logging.debug(f"Root directory: {root_dir}")
    logging.debug(f"Target file: {target_file}")
    logging.debug(f"Ignore patterns: {ignore_patterns}")
    logging.debug(f"Checking write permissions: {check_write}")


    paths = find_potential_paths(root_dir, target_file, user, ignore_patterns, check_write)

    if paths:
        logging.info("Potential permission exfiltration paths found:")
        if HAS_RICH:
            console = Console()
            table = Table(title="Permission Exfiltration Paths")
            table.add_column("Path Number", justify="right", style="cyan", no_wrap=True)
            table.add_column("Path", style="magenta")
            for i, path in enumerate(paths):
                table.add_row(str(i + 1), " -> ".join(path))
            console.print(table)
        else:
            for i, path in enumerate(paths):
                print(f"Path {i + 1}: {' -> '.join(path)}")
    else:
        logging.info("No potential permission exfiltration paths found.")

if __name__ == "__main__":
    # Example usage:
    # Create some dummy files and directories for testing
    # mkdir -p /tmp/test/dir1/dir2
    # touch /tmp/test/dir1/dir2/target.txt
    # python pa_permission_exfiltration_path_analyzer.py -r /tmp/test -t /tmp/test/dir1/dir2/target.txt -u myuser
    # python pa_permission_exfiltration_path_analyzer.py -r /tmp/test -t /tmp/test/dir1/dir2/target.txt -u myuser -i "*/dir1/*"
    # python pa_permission_exfiltration_path_analyzer.py -r /tmp/test -t /tmp/test/dir1/dir2/target.txt -u myuser --check-write
    # python pa_permission_exfiltration_path_analyzer.py -r /tmp/test -t /tmp/test/dir1/dir2/target.txt -u myuser -v
    main()