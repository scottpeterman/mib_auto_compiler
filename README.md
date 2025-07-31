# MIB Auto Compiler

**Automatic SNMP MIB dependency resolution and compilation for Python applications**

MIB Auto Compiler is a powerful tool that automatically downloads standard MIB dependencies and compiles vendor-specific MIBs into Python modules for use with PySNMP applications. It eliminates the tedious process of manually managing MIB dependencies and provides a seamless way to work with vendor MIBs in your Python SNMP applications.

## Features

- **Automatic Dependency Resolution**: Automatically downloads and resolves standard MIB dependencies
- **Multi-Source Download**: Supports multiple MIB download sources with fallback mechanisms  
- **Retry Logic**: Intelligent retry mechanism for failed compilations with dependency auto-download
- **Rich CLI Interface**: Beautiful command-line interface with progress bars and detailed reporting
- **Flexible Configuration**: YAML/JSON configuration files with environment variable support
- **Vendor Support**: Pre-configured support for major vendors (Cisco, Juniper, Arista, etc.)
- **Comprehensive Validation**: Built-in MIB file validation with detailed syntax checking
- **Multiple Output Formats**: Text and JSON reporting with extensible format support
- **Python API**: Full programmatic API for library integration
- **Dependency Analysis**: Visual dependency graphs and circular dependency detection
- **OID Discovery**: Extract network discovery OIDs from compiled MIBs
- **Caching System**: Smart caching of downloaded standard MIBs for reuse
- **Performance Monitoring**: Detailed compilation statistics and timing information

## Installation

### From PyPI (Soon)

```bash
pip install mib-auto-compiler
```

### From Source

```bash
git clone https://github.com/yourusername/mib-auto-compiler.git
cd mib-auto-compiler
pip install -e .
```

### Development Installation

```bash
git clone https://github.com/yourusername/mib-auto-compiler.git
cd mib-auto-compiler
pip install -e ".[dev]"
```

## 🔧 Quick Start

### Command Line Usage

1. **Basic compilation** - Compile all MIBs in a directory:

```bash
mib-compile /path/to/vendor/mibs
```

2. **Specify output directory**:

```bash
mib-compile /path/to/vendor/mibs -o /path/to/output
```

3. **Compile specific MIBs**:

```bash
mib-compile /path/to/vendor/mibs -m CISCO-SMI -m CISCO-ENTITY-MIB
```

4. **Use configuration file**:

```bash
mib-compile /path/to/vendor/mibs --config my-config.yaml
```

5. **Generate configuration template**:

```bash
mib-compile init-config --template advanced -o my-config.yaml
```

### Python API Usage

```python
from mib_auto_compiler import MibAutoCompiler
from mib_auto_compiler.config import CompilerConfig

# Create configuration
config = CompilerConfig(
    output_directory="./compiled_mibs",
    max_retries=5,
    preserve_downloads=True
)

# Initialize compiler
compiler = MibAutoCompiler(
    vendor_mib_directory="/path/to/vendor/mibs",
    config=config
)

# Run compilation
results = compiler.run_auto_compilation()

# Check results
for mib_name, result in results.items():
    if result['success']:
        print(f"✓ {mib_name} compiled successfully")
    else:
        print(f"✗ {mib_name} failed: {result['message']}")

# Get compiled files
compiled_files = compiler.get_compiled_mibs()
print(f"Compiled {len(compiled_files)} MIBs to: {compiler.compiled_dir}")
```

## Command Reference

### Main Commands

#### `mib-compile compile`

Compile vendor MIBs with automatic dependency resolution.

```bash
mib-compile compile [OPTIONS] VENDOR_MIB_DIRECTORY
```

**Options:**
- `-o, --output PATH`: Output directory for compiled MIBs
- `-c, --config PATH`: Configuration file path
- `-m, --mibs TEXT`: Specific MIBs to compile (multiple allowed)
- `-r, --retries INTEGER`: Maximum retry attempts (default: 3)
- `-t, --timeout INTEGER`: Download timeout in seconds (default: 10)
- `--no-http-fallback`: Disable HTTP MIB source fallback
- `--preserve-downloads/--no-preserve-downloads`: Keep downloaded MIBs (default: keep)
- `--report-format [text|json|html]`: Output report format (default: text)
- `--report-file PATH`: Save report to file

#### `mib-compile analyze`

Analyze MIB files without compilation.

```bash
mib-compile analyze [OPTIONS] MIB_DIRECTORY
```

**Options:**
- `--format [text|json|yaml]`: Output format (default: text)
- `-o, --output PATH`: Output file (default: stdout)
- `--include-dependencies`: Show dependency analysis
- `--include-objects`: Include object type details

#### `mib-compile init-config`

Generate configuration file template.

```bash
mib-compile init-config [OPTIONS]
```

**Options:**
- `--template [basic|advanced|enterprise]`: Template type (default: basic)
- `-o, --output PATH`: Output file (default: mib-compiler.yaml)

#### `mib-compile extract-oids`

Extract discovery OIDs from compiled MIB files.

```bash
mib-compile extract-oids [OPTIONS] COMPILED_DIRECTORY
```

**Options:**
- `--format [text|json]`: Output format (default: text)
- `--filter TEXT`: OID name filter patterns (regex, multiple allowed)

### Global Options

- `-v, --verbose`: Enable verbose logging
- `-q, --quiet`: Suppress info messages
- `--version`: Show version information
- `-h, --help`: Show help message

## Configuration

### Configuration File

MIB Auto Compiler supports YAML and JSON configuration files:

```yaml
# mib-compiler.yaml
output_directory: "./compiled_mibs"
max_retries: 5
download_timeout: 15
enable_http_fallback: true
preserve_downloads: true
validate_before_compile: true

log_level: "INFO"
log_to_file: true
log_file_path: "./logs/mib_compiler.log"

generate_reports: true
report_formats: ["text", "json"]
include_statistics: true

mib_sources:
  - "https://mibs.pysnmp.com/asn1/"
  - "https://www.circitor.fr/Mibs/Mib/"
  - "https://raw.githubusercontent.com/librenms/librenms/master/mibs/"

standard_mibs:
  - "SNMPv2-SMI"
  - "SNMPv2-TC"
  - "SNMPv2-CONF"
  - "IF-MIB"
  - "IP-MIB"
  # ... more MIBs

vendor_specific:
  cisco:
    additional_sources:
      - "https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/"
    priority_mibs:
      - "CISCO-SMI"
      - "CISCO-TC"
```

### Environment Variables

Configuration can be overridden with environment variables:

```bash
export MIB_COMPILER_OUTPUT_DIR="/path/to/output"
export MIB_COMPILER_MAX_RETRIES=5
export MIB_COMPILER_TIMEOUT=15
export MIB_COMPILER_LOG_LEVEL="DEBUG"
export MIB_COMPILER_SOURCES="https://example.com/mibs/,https://another.com/mibs/"
```

## Vendor Support

MIB Auto Compiler includes pre-configured support for major network vendors:

### Supported Vendors

- **Cisco**: Automatic download of Cisco MIBs and SMI files
- **Juniper**: Support for Juniper enterprise MIBs
- **Arista**: Arista EOS MIB support
- **Dell/Force10**: Dell networking MIBs
- **HP/HPE**: HP enterprise MIBs
- **Huawei**: Huawei enterprise MIBs
- **Fortinet**: FortiGate MIBs
- **Palo Alto**: Palo Alto Networks MIBs

### Adding Vendor Support

You can add custom vendor support through configuration:

```yaml
vendor_specific:
  my_vendor:
    additional_sources:
      - "https://myvendor.com/mibs/"
    priority_mibs:
      - "MY-VENDOR-SMI"
      - "MY-VENDOR-PRODUCTS-MIB"
    custom_settings:
      special_handling: true
```

## Use Cases

### Network Monitoring Applications

```python
from mib_auto_compiler import MibAutoCompiler

# Compile MIBs for monitoring application
compiler = MibAutoCompiler("/path/to/cisco/mibs")
results = compiler.run_auto_compilation()

# Use compiled MIBs with PySNMP
import sys
sys.path.insert(0, str(compiler.compiled_dir))

from pysnmp.smi import builder, view
mib_builder = builder.MibBuilder()
mib_builder.add_module_to_path(str(compiler.compiled_dir))
```

### Automated CI/CD Pipeline

```bash
#!/bin/bash
# Download vendor MIBs
curl -o cisco-mibs.zip "https://vendor.com/mibs.zip"
unzip cisco-mibs.zip

# Compile MIBs
mib-compile ./cisco-mibs --config production.yaml --report-format json --report-file results.json

# Deploy compiled MIBs
cp -r compiled/* /app/mibs/
```

### Development and Testing

```python
import tempfile
from mib_auto_compiler import MibAutoCompiler
from mib_auto_compiler.config import CompilerConfig

# Quick testing setup
with tempfile.TemporaryDirectory() as temp_dir:
    config = CompilerConfig(
        output_directory=temp_dir,
        preserve_downloads=False
    )
    
    compiler = MibAutoCompiler("./test_mibs", config=config)
    results = compiler.run_auto_compilation()
    
    # Test with compiled MIBs
    test_snmp_operations(compiler.get_compiled_mibs())
```

## Troubleshooting

### Common Issues

1. **Missing Dependencies**
   ```
   Error: cannot locate CISCO-SMI
   Solution: Ensure vendor SMI files are included or use --no-http-fallback
   ```

2. **Download Failures**
   ```
   Error: Failed to download from all sources
   Solution: Check network connectivity or add custom MIB sources
   ```

3. **Compilation Errors**
   ```
   Error: Syntax error in MIB file
   Solution: Use --validate-before-compile to identify issues
   ```

### Debug Mode

Enable verbose logging for detailed troubleshooting:

```bash
mib-compile -v compile /path/to/mibs
```

Or set log level in configuration:

```yaml
log_level: "DEBUG"
log_to_file: true
log_file_path: "debug.log"
```

### Getting Help

- Check the [documentation](https://mib-auto-compiler.readthedocs.io/)

## Testing

Run the test suite:

```bash
# Install test dependencies
pip install -e ".[test]"

# Run tests
pytest

# Run with coverage
pytest --cov=mib_auto_compiler --cov-report=html
```


## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md).

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/mib-auto-compiler.git
cd mib-auto-compiler

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Run tests
pytest
```

### Code Style

We use Black for code formatting and flake8 for linting:

```bash
# Format code
black mib_auto_compiler tests

# Check linting
flake8 mib_auto_compiler tests

# Type checking
mypy mib_auto_compiler
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [PySMI](https://github.com/etingof/pysmi) - The underlying MIB compilation library
- [PySNMP](https://github.com/etingof/pysnmp) - Python SNMP library
- [Rich](https://github.com/willmcgugan/rich) - Beautiful terminal formatting
- [Click](https://click.palletsprojects.com/) - Command line interface creation


---

**Made with care for the Python SNMP community**