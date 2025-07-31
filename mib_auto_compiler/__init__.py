"""
MIB Auto Compiler - Automatic SNMP MIB dependency resolution and compilation

This package provides automatic downloading of standard MIB dependencies
and compilation of vendor-specific MIBs into Python modules for use with
PySNMP applications.

Key Features:
- Automatic dependency resolution
- Multi-source MIB downloading with fallback
- Intelligent retry logic for failed compilations
- Rich CLI interface with progress tracking
- Flexible configuration system
- Comprehensive validation and reporting

Basic Usage:
    >>> from mib_auto_compiler import MibAutoCompiler
    >>> compiler = MibAutoCompiler("/path/to/vendor/mibs")
    >>> results = compiler.run_auto_compilation()
    >>> print(f"Compiled {len([r for r in results.values() if r['success']])} MIBs")

CLI Usage:
    $ mib-compile /path/to/vendor/mibs --output /path/to/output
"""

from .__version__ import (
    __version__,
    __version_info__,
    __title__,
    __description__,
    __author__,
    __author_email__,
    __license__,
    __url__,
    get_version,
    get_version_info
)

from .core import MibAutoCompiler
from .config import CompilerConfig, create_default_config, find_config_file
from .downloaders import MibDownloadManager
from .utils import (
    MibValidator,
    extract_mib_dependencies,
    extract_mib_info,
    analyze_mib_directory,
    sort_mibs_by_dependencies,
    validate_compiled_mib,
    extract_discovery_oids,
    create_mib_summary_report
)
from .exceptions import (
    MibAutoCompilerError,
    MibDownloadError,
    MibCompilationError,
    MibDependencyError,
    MibValidationError,
    MibCompilerSetupError,
    MibProcessingError,
    MibNetworkError
)

# Main public API
__all__ = [
    # Version information
    '__version__',
    '__version_info__',
    'get_version',
    'get_version_info',

    # Core classes
    'MibAutoCompiler',
    'CompilerConfig',
    'MibDownloadManager',
    'MibValidator',

    # Configuration utilities
    'create_default_config',
    'find_config_file',

    # Utility functions
    'extract_mib_dependencies',
    'extract_mib_info',
    'analyze_mib_directory',
    'sort_mibs_by_dependencies',
    'validate_compiled_mib',
    'extract_discovery_oids',
    'create_mib_summary_report',

    # Exceptions
    'MibAutoCompilerError',
    'MibDownloadError',
    'MibCompilationError',
    'MibDependencyError',
    'MibValidationError',
    'MibCompilerSetupError',
    'MibProcessingError',
    'MibNetworkError',
]

# Package metadata
__package_name__ = __title__
__summary__ = __description__

# Ensure pysmi is available
try:
    import pysmi

    _PYSMI_AVAILABLE = True
except ImportError:
    _PYSMI_AVAILABLE = False

if not _PYSMI_AVAILABLE:
    import warnings

    warnings.warn(
        "pysmi is not installed. MIB compilation will not work. "
        "Install with: pip install pysmi",
        ImportWarning,
        stacklevel=2
    )

# Setup logging
import logging

logging.getLogger(__name__).addHandler(logging.NullHandler())


def get_package_info() -> dict:
    """Get comprehensive package information"""
    info = get_version_info()
    info.update({
        'package_name': __package_name__,
        'pysmi_available': _PYSMI_AVAILABLE,
        'main_classes': ['MibAutoCompiler', 'CompilerConfig', 'MibDownloadManager'],
        'cli_commands': ['mib-compile', 'mib-auto-compile'],
    })

    # Add dependency information
    try:
        import pysnmp
        info['pysnmp_version'] = pysnmp.__version__
    except (ImportError, AttributeError):
        info['pysnmp_version'] = 'not available'

    if _PYSMI_AVAILABLE:
        try:
            info['pysmi_version'] = pysmi.__version__
        except AttributeError:
            info['pysmi_version'] = 'unknown'
    else:
        info['pysmi_version'] = 'not available'

    return info


def check_dependencies() -> dict:
    """Check if all required dependencies are available"""
    deps = {
        'pysmi': {'available': False, 'version': None, 'required': True},
        'pysnmp': {'available': False, 'version': None, 'required': True},
        'requests': {'available': False, 'version': None, 'required': True},
        'click': {'available': False, 'version': None, 'required': True},
        'rich': {'available': False, 'version': None, 'required': True},
        'pydantic': {'available': False, 'version': None, 'required': True},
        'yaml': {'available': False, 'version': None, 'required': False},
    }

    # Check each dependency
    for dep_name, dep_info in deps.items():
        try:
            if dep_name == 'yaml':
                import yaml
                dep_info['available'] = True
                dep_info['version'] = getattr(yaml, '__version__', 'unknown')
            else:
                module = __import__(dep_name)
                dep_info['available'] = True
                dep_info['version'] = getattr(module, '__version__', 'unknown')
        except ImportError:
            pass

    return deps


# Convenience function for quick compilation
def compile_mibs(vendor_mib_directory: str,
                 output_directory: str = None,
                 config: CompilerConfig = None,
                 **kwargs) -> dict:
    """
    Convenience function for quick MIB compilation

    Args:
        vendor_mib_directory: Path to vendor MIB files
        output_directory: Optional output directory
        config: Optional configuration object
        **kwargs: Additional arguments passed to MibAutoCompiler

    Returns:
        Dictionary of compilation results

    Example:
        >>> results = compile_mibs("/path/to/mibs", output_directory="/path/to/output")
        >>> successful = sum(1 for r in results.values() if r['success'])
        >>> print(f"Compiled {successful}/{len(results)} MIBs successfully")
    """
    compiler = MibAutoCompiler(
        vendor_mib_directory=vendor_mib_directory,
        output_directory=output_directory,
        config=config,
        **kwargs
    )

    return compiler.run_auto_compilation()


# Add convenience function to __all__
__all__.append('compile_mibs')