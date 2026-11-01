# pa-permission-exfiltration-path-analyzer
Analyzes potential paths to sensitive data based on existing permissions. Identifies chains of permission grants that could allow unintended access to critical resources. Despite the name, this tool moves no data: it reads permission modes under the root directory the operator names and prints the paths it finds to the console only. - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowGuardAI/pa-permission-exfiltration-path-analyzer`

## Usage
`python3 main.py -r [root] -t [target] -u [user] [params]`

## Parameters
- `-h`: Show help message and exit
- `-r`: Root directory to start the analysis from. Defaults to current directory.
- `-u`: User to simulate access for. The user must exist on this system.
- `-t`: Target file or directory to check access to. The target must exist.
- `-i`: List of glob patterns to ignore (e.g., '*.tmp' '*/temp/*'). Patterns are matched against paths relative to the root directory.
- `-v`: Enable verbose output.
- `--check-write`: Check for write access instead of read access.

## Behavior notes
- The named user selects the identity whose access is tested. For each path, the permission class that applies to that user is used: the owner bits when the user owns the entry, the group bits when the user belongs to the entry's group (primary group or a group listing the user as a member), and the other bits otherwise. ACLs are not consulted. A user name that does not exist ends the run with an error and exit 1.
- A path is reported only when the walk reaches the target itself and the named user's permission check passes on the target's own entry, so a reported path ends at the target, not at the directory holding it. A target that does not exist is an error: the run prints that no analysis was run and exits 1, and no path is reported for it.

## License
Copyright (c) ShadowGuardAI
