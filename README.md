# pa-permission-exfiltration-path-analyzer
Analyzes potential paths to sensitive data based on existing permissions. Identifies chains of permission grants that could allow unintended access to critical resources. - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowGuardAI/pa-permission-exfiltration-path-analyzer`

## Usage
`./pa-permission-exfiltration-path-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-r`: Root directory to start the analysis from. Defaults to current directory.
- `-u`: User to simulate access for.
- `-t`: Target file or directory to check access to.
- `-i`: List of glob patterns to ignore (e.g., 
- `-v`: Enable verbose output.
- `--check-write`: Check for write access instead of read access.

## License
Copyright (c) ShadowGuardAI
