# mib_auto_downloader/__init__.py
"""
MIB Auto-Downloader - Automatic SNMP MIB dependency resolution and compilation
"""
#
# __version__ = "1.0.0"
# __author__ = "Your Name"
# __email__ = "your.email@example.com"
#
# from .core import MibAutoDownloader
# from .downloaders import MibDownloadManager
# from .utils import MibValidator, extract_mib_dependencies
# from .exceptions import (
#     MibDownloadError,
#     MibCompilationError,
#     MibDependencyError
# )

# __all__ = [
#     'MibAutoDownloader',
#     'MibDownloadManager',
#     'MibValidator',
#     'extract_mib_dependencies',
#     'MibDownloadError',
#     'MibCompilationError',
#     'MibDependencyError'
# ]

# ============================================================================
# mib_auto_downloader/core.py
"""
Core MIB auto-compilation functionality
"""

import os
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging

from .downloaders import MibDownloadManager
from .utils import MibValidator, extract_mib_dependencies
from .exceptions import MibCompilationError

logger = logging.getLogger(__name__)

try:
    from pysmi.reader import FileReader, HttpReader
    from pysmi.searcher import StubSearcher
    from pysmi.writer import PyFileWriter
    from pysmi.parser import SmiStarParser
    from pysmi.codegen import PySnmpCodeGen
    from pysmi.compiler import MibCompiler
except ImportError as e:
    raise ImportError(f"pysmi is required: {e}")


class MibAutoDownloader:
    """
    Main class for automatic MIB compilation with dependency resolution
    """

    def __init__(self,
                 vendor_mib_directory: str,
                 output_directory: Optional[str] = None,
                 max_retries: int = 3,
                 download_timeout: int = 10,
                 enable_http_fallback: bool = True,
                 preserve_downloads: bool = True,
                 verbose: bool = False):
        """
        Initialize MIB auto-downloader

        Args:
            vendor_mib_directory: Path to vendor MIB files
            output_directory: Custom output directory (optional)
            max_retries: Maximum compilation retry attempts
            download_timeout: Download timeout in seconds
            enable_http_fallback: Enable HTTP MIB source fallback
            preserve_downloads: Keep downloaded MIBs for reuse
            verbose: Enable verbose logging
        """
        self.vendor_mib_dir = Path(vendor_mib_directory)
        self.max_retries = max_retries
        self.enable_http_fallback = enable_http_fallback
        self.preserve_downloads = preserve_downloads

        if verbose:
            logging.getLogger().setLevel(logging.DEBUG)

        # Setup working directories
        if output_directory:
            self.work_dir = Path(output_directory)
            self.work_dir.mkdir(exist_ok=True)
        else:
            self.work_dir = Path(tempfile.mkdtemp(prefix="mib_auto_compile_"))

        self.standard_mib_dir = self.work_dir / "standard_mibs"
        self.compiled_dir = self.work_dir / "compiled"

        self.standard_mib_dir.mkdir(exist_ok=True)
        self.compiled_dir.mkdir(exist_ok=True)

        # Initialize components
        self.download_manager = MibDownloadManager(
            self.standard_mib_dir,
            timeout=download_timeout
        )
        self.validator = MibValidator()

        logger.info(f"Working directory: {self.work_dir}")

    def add_mib_source(self, url: str):
        """Add custom MIB download source"""
        self.download_manager.add_source(url)

    def add_standard_mib(self, mib_name: str):
        """Add MIB to standard download list"""
        self.download_manager.add_standard_mib(mib_name)

    def set_standard_mibs(self, mib_list: List[str]):
        """Set custom list of standard MIBs"""
        self.download_manager.set_standard_mibs(mib_list)

    def download_dependencies(self) -> int:
        """Download all standard MIB dependencies"""
        return self.download_manager.download_all_standard_mibs()

    def setup_compiler(self) -> bool:
        """Setup pysmi compiler with all sources"""
        try:
            self.compiler = MibCompiler(
                SmiStarParser(),
                PySnmpCodeGen(),
                PyFileWriter(str(self.compiled_dir))
            )

            # Add MIB sources
            self.compiler.add_sources(FileReader(str(self.vendor_mib_dir)))
            self.compiler.add_sources(FileReader(str(self.standard_mib_dir)))

            # Add HTTP fallback if enabled
            if self.enable_http_fallback:
                try:
                    self.compiler.add_sources(HttpReader('https://mibs.pysnmp.com/asn1/@mib@'))
                    logger.info("Added HTTP MIB source")
                except Exception as e:
                    logger.warning(f"Could not add HTTP source: {e}")

            # Add built-in searchers
            self.compiler.add_searchers(StubSearcher(*PySnmpCodeGen.defaultMibPackages))

            logger.info("Compiler setup completed")
            return True

        except Exception as e:
            logger.error(f"Failed to setup compiler: {e}")
            return False

    def compile_mib_with_deps(self, mib_name: str) -> Tuple[bool, str]:
        """Compile MIB with automatic dependency resolution"""
        for attempt in range(self.max_retries):
            logger.info(f"Compiling {mib_name} (attempt {attempt + 1}/{self.max_retries})")

            try:
                results = self.compiler.compile(mib_name)

                if mib_name in results:
                    result = results[mib_name]

                    if result == 'compiled':
                        py_file = self.compiled_dir / f"{mib_name}.py"
                        if py_file.exists():
                            size = py_file.stat().st_size
                            logger.info(f"✓ {mib_name} compiled successfully ({size} bytes)")
                            return True, "compiled"

                    elif isinstance(result, Exception):
                        error_msg = str(result)
                        logger.warning(f"Compilation error for {mib_name}: {error_msg}")

                        # Try to download missing dependency
                        missing_mib = self._extract_missing_mib(error_msg)
                        if missing_mib:
                            logger.info(f"Attempting to download missing dependency: {missing_mib}")
                            if self.download_manager.download_mib(missing_mib):
                                continue  # Retry compilation

                        return False, error_msg
                    else:
                        return False, str(result)
                else:
                    return False, "no result"

            except Exception as e:
                logger.error(f"Exception during compilation of {mib_name}: {e}")
                return False, str(e)

        return False, f"Failed after {self.max_retries} attempts"

    def compile_vendor_mibs(self, mib_list: Optional[List[str]] = None) -> Dict[str, Dict]:
        """Compile specified vendor MIBs or auto-detect"""
        if mib_list is None:
            # Auto-detect MIB files
            mib_files = list(self.vendor_mib_dir.glob("*.mib"))
            mib_list = [f.stem for f in mib_files]

            # Try to sort by dependencies
            mib_list = self._sort_by_dependencies(mib_list)

        logger.info(f"Compiling {len(mib_list)} vendor MIBs...")

        results = {}
        for mib_name in mib_list:
            success, message = self.compile_mib_with_deps(mib_name)
            results[mib_name] = {'success': success, 'message': message}

            if not success:
                logger.warning(f"Failed to compile {mib_name}: {message}")

        return results

    def get_compiled_mibs(self) -> List[Path]:
        """Get list of successfully compiled Python modules"""
        return list(self.compiled_dir.glob("*.py"))

    def run_auto_compilation(self, mib_list: Optional[List[str]] = None) -> bool:
        """Run complete auto-compilation process"""
        logger.info("Starting MIB auto-compilation with dependency download...")

        # Download dependencies
        downloaded = self.download_dependencies()
        if downloaded == 0:
            logger.warning("No standard MIBs downloaded - compilation may fail")

        # Setup compiler
        if not self.setup_compiler():
            logger.error("Compiler setup failed")
            return False

        # Compile vendor MIBs
        results = self.compile_vendor_mibs(mib_list)

        # Generate report
        self._generate_report(results)

        return any(r['success'] for r in results.values())

    def _extract_missing_mib(self, error_msg: str) -> Optional[str]:
        """Extract missing MIB name from error message"""
        import re

        patterns = [
            r"cannot locate (\w+(?:-\w+)*)",
            r"No module named '(\w+(?:-\w+)*)'",
            r"ImportError.*'(\w+(?:-\w+)*)'",
            r"MIB file.*'(\w+(?:-\w+)*)'.*not found"
        ]

        for pattern in patterns:
            match = re.search(pattern, error_msg, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def _sort_by_dependencies(self, mib_list: List[str]) -> List[str]:
        """Sort MIBs by dependency order"""
        # Simple heuristic: SMI files first, then others
        smis = [m for m in mib_list if 'SMI' in m.upper()]
        others = [m for m in mib_list if 'SMI' not in m.upper()]
        return smis + others

    def _generate_report(self, results: Dict[str, Dict]):
        """Generate compilation report"""
        logger.info("\n" + "=" * 70)
        logger.info("MIB AUTO-COMPILATION FINAL REPORT")
        logger.info("=" * 70)

        successful = sum(1 for r in results.values() if r['success'])
        total = len(results)

        logger.info(f"Compilation Success Rate: {successful}/{total} ({successful / total * 100:.1f}%)")

        logger.info("\nDetailed Results:")
        for mib_name, result in results.items():
            status = "✓ PASS" if result['success'] else "✗ FAIL"
            logger.info(f"  {status:<8} {mib_name:<20} {result['message']}")

        # Show downloaded files
        downloaded_files = list(self.standard_mib_dir.glob("*.mib"))
        if downloaded_files:
            logger.info(f"\nDownloaded Standard MIBs ({len(downloaded_files)}):")
            for mib_file in sorted(downloaded_files):
                size = mib_file.stat().st_size
                logger.info(f"  {mib_file.stem:<25} {size:>8} bytes")

        # Show compiled files
        compiled_files = list(self.compiled_dir.glob("*.py"))
        if compiled_files:
            logger.info(f"\nCompiled Output Files ({len(compiled_files)}):")
            for py_file in sorted(compiled_files):
                size = py_file.stat().st_size
                logger.info(f"  {py_file.stem:<25} {size:>8} bytes")

        logger.info(f"\nAll files saved to: {self.work_dir}")

        if successful > 0:
            logger.info(f"\n🎉 Success! {successful} MIB(s) compiled with auto-downloaded dependencies!")
        else:
            logger.info(f"\n❌ No MIBs compiled successfully. Check error messages above.")

