# Unblock

A Python-based project analysis tool that uses LLM-powered scanners to identify potential blockers and authentication flows in your codebase.

## Description

Unblock is an intelligent code scanning utility that leverages Language Models to analyze projects for common development blockers, authentication patterns, CI/CD configurations, and Git workflows. It provides automated insights to help developers identify and resolve potential issues in their projects.

## Tech Stack

- **Language:** Python 3.x
- **Core Technologies:**
  - LLM Integration (Language Model Pool)
  - CLI Interface
  - Caching System
  - Multi-scanner Architecture
- **Project Management:** Poetry (pyproject.toml)

## Installation

### Prerequisites

- Python 3.8 or higher
- pip or Poetry package manager

### Install with pip

```bash
pip install -e .
```

### Install with Poetry

```bash
poetry install
```

## Usage

### Basic Command

```bash
unblock [options]
```

### Running Scanners

The tool includes multiple specialized scanners:

- **Auth Flow Scanner** - Analyzes authentication and authorization patterns
- **CI Scanner** - Examines CI/CD configuration and workflows
- **Git Scanner** - Reviews Git repository structure and history
- **LLM Auth Scanner** - Uses LLM to identify authentication-related issues

### Configuration

Configure Unblock by setting up your configuration file. The tool uses a caching system to optimize repeated scans and improve performance.

### Example Workflow

```bash
# Scan current project
unblock

# View detailed output with banner information
unblock --verbose

# Clear cache before scanning
unblock --clear-cache
```

## Project Structure

```
unblock/
├── __init__.py           # Package initialization
├── cache.py              # Caching system for scan results
├── cli.py                # Command-line interface
├── config.py             # Configuration management
├── llm_pool.py           # LLM connection pooling
├── scoring.py            # Scoring and ranking system
├── output/
│   ├── __init__.py
│   └── banner.py         # Output formatting and banners
└── scanners/
    ├── __init__.py
    ├── base.py           # Base scanner class
    ├── auth_flow_scanner.py
    ├── ci_scanner.py
    ├── git_scanner.py
    └── llm_auth_scanner.py
```

## License

MIT License
