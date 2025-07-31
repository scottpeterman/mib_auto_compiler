"""
Version information for MIB Auto Compiler
"""

__version__ = "0.1.0"
__version_info__ = (0, 1, 0)

# Package metadata
__title__ = "mib-auto-compiler"
__description__ = "Automatic SNMP MIB dependency resolution and compilation for Python applications"
__author__ = "Scott"
__author_email__ = "scottpeterman@gmail.com"
__license__ = "MIT"
__copyright__ = "Copyright 2024"
__url__ = "https://github.com/scottpeterman/mib-auto-compiler"

# Build information (can be updated by CI/CD)
__build__ = None
__build_date__ = None
__commit__ = None

def get_version() -> str:
    """Get the version string"""
    version = __version__
    if __build__:
        version += f"+{__build__}"
    return version

def get_version_info() -> dict:
    """Get detailed version information"""
    return {
        "version": __version__,
        "version_info": __version_info__,
        "title": __title__,
        "description": __description__,
        "author": __author__,
        "author_email": __author_email__,
        "license": __license__,
        "copyright": __copyright__,
        "url": __url__,
        "build": __build__,
        "build_date": __build_date__,
        "commit": __commit__,
    }