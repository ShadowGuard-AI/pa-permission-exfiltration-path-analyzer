#!/usr/bin/env python3
"""
pa-permission-exfiltration-path-analyzer

Analyzes potential paths to sensitive data based on existing permissions.
Identifies chains of permission grants that could allow unintended access to critical resources.
"""

import argparse
import logging
import os
import sys
from typing import List, Dict, Any

# Optional dependencies (install with pip install pathspec rich)
try:
    import pathspec
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


def check_permission(filepath: str, user: str, check_write: bool = False) -> bool:
    """
    Checks if a user has read or write permissions to a file.  This is a simplified
    implementation and does not cover all possible permission scenarios.

    Args:
        filepath (str): The path to the file.
        user (str): The user to check permissions for.
        check_write (bool): If True, check for write access instead of read.

    Returns:
        bool: True if the user has the specified permissions, False otherwise.
    """

    try:
        # Basic check: Does the user have read or write permissions based on file mode?
        # This is a simplification and will need to be expanded for real-world use cases.
        mode = os.stat(filepath).st_mode
        uid = os.stat(filepath).st_uid
        gid = os.stat(filepath).st_gid
        user_id = os.getuid()  # Assuming current user ID for simplicity

        # Check if the user is the owner and has appropriate permissions.
        if user_id == uid:
            if check_write:
                if mode & 0o200: # Owner write
                    return True
            else:
                if mode & 0o400: # Owner read
                    return True

        # Expand this logic based on real-world scenarios (ACLs, groups, etc.).
        # This is a placeholder and needs significant expansion for practical use.
        # Consider using libraries like `acl` (linux) for handling ACLs.
        return False # Default to False if no explicit permission found
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
        ignore_spec = pathspec.PathSpec.from_glob(ignore_patterns)

    def explore_path(current_path: List[str], current_dir: str):
        """Recursive helper function to explore the directory tree."""
        nonlocal paths

        if ignore_spec and ignore_spec.match_file(current_dir):
            logging.debug(f"Ignoring directory: {current_dir}")
            return

        if not check_permission(current_dir, user, check_write):
            logging.debug(f"No access to {current_dir} for {user}")
            return

        current_path.append(current_dir)  # Add current directory to the path

        if os.path.abspath(current_dir) == os.path.abspath(target_file) or os.path.join(current_dir, os.path.basename(target_file)) == target_file:
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

    if not os.path.exists(target_file):
         logging.warning(f"Target file '{target_file}' does not exist. Continuing search for potential paths leading to it.")
         # sys.exit(1)  # Commented out so that we can continue looking for path prefixes that might eventually lead to a target_file that will exist in the future.

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