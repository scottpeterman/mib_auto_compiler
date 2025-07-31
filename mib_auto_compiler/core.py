"""
Core MIB auto-compilation functionality
"""

import os
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Any
import logging
import time
from datetime import datetime

from .downloaders import MibDownloadManager
from .utils import (
    MibValidator,
    extract_mib_dependencies,
    sort_mibs_by_dependencies,
    analyze_mib_directory
)
from .config import CompilerConfig
from .exceptions import (
    MibAutoCompilerError,
    MibCompilationError,
    MibCompilerSetupError,
    raise_compilation_failed
)

logger = logging.getLogger(__name__)

try:
    from pysmi.reader import FileReader, HttpReader
    from pysmi.searcher import StubSearcher
    from pysmi.writer import PyFileWriter
    from pysmi.parser import SmiStarParser
    from pysmi.codegen import PySnmpCodeGen
    from pysmi.compiler import MibCompiler
except ImportError as e:
    raise ImportError(f"pysmi is required: {e}. Install with: pip install pysmi")


class MibAutoCompiler:
    """
    Main class for automatic MIB compilation with dependency resolution

    This class provides a comprehensive solution for:
    - Automatic standard MIB dependency downloading
    - Vendor MIB compilation with retry logic
    - Dependency resolution and circular dependency detection
    - Progress tracking and detailed reporting
    - Configurable output formats and locations
    """

    def __init__(self,
                 vendor_mib_directory: str,
                 config: Optional[CompilerConfig] = None,
                 output_directory: Optional[str] = None,
                 verbose: bool = False):
        """
        Initialize MIB auto-compiler

        Args:
            vendor_mib_directory: Path to vendor MIB files
            config: Optional configuration object
            output_directory: Custom output directory (overrides config)
            verbose: Enable verbose logging
        """
        self.vendor_mib_dir = Path(vendor_mib_directory)
        if not self.vendor_mib_dir.exists():
            raise MibAutoCompilerError(f"Vendor MIB directory not found: {vendor_mib_directory}")

        # Load configuration
        self.config = config or CompilerConfig()

        if verbose:
            logging.getLogger().setLevel(logging.DEBUG)

        # Setup working directories
        if output_directory:
            self.work_dir = Path(output_directory)
            self.work_dir.mkdir(parents=True, exist_ok=True)
        elif self.config.output_directory:
            self.work_dir = Path(self.config.output_directory)
            self.work_dir.mkdir(parents=True, exist_ok=True)
        else:
            self.work_dir = Path(tempfile.mkdtemp(prefix="mib_auto_compile_"))

        # Create subdirectories
        self.standard_mib_dir = self.work_dir / "standard_mibs"
        self.compiled_dir = self.work_dir / "compiled"
        self.logs_dir = self.work_dir / "logs"

        for directory in [self.standard_mib_dir, self.compiled_dir, self.logs_dir]:
            directory.mkdir(exist_ok=True)

        # Initialize components
        self.download_manager = MibDownloadManager(
            self.standard_mib_dir,
            timeout=self.config.download_timeout
        )

        # Configure download sources
        for source in self.config.mib_sources:
            self.download_manager.add_source(source)

        # Configure standard MIBs
        if self.config.standard_mibs:
            self.download_manager.set_standard_mibs(self.config.standard_mibs)

        self.validator = MibValidator()
        self.compiler = None

        # Statistics tracking
        self.stats = {
            'start_time': None,
            'end_time': None,
            'duration': 0,
            'mibs_processed': 0,
            'mibs_successful': 0,
            'mibs_failed': 0,
            'dependencies_downloaded': 0,
            'total_size_bytes': 0,
            'errors': []
        }

        logger.info(f"MIB Auto Compiler initialized")
        logger.info(f"Vendor MIB directory: {self.vendor_mib_dir}")
        logger.info(f"Working directory: {self.work_dir}")

    def add_mib_source(self, url: str) -> None:
        """Add custom MIB download source"""
        self.download_manager.add_source(url)
        logger.info(f"Added MIB source: {url}")

    def add_standard_mib(self, mib_name: str) -> None:
        """Add MIB to standard download list"""
        self.download_manager.add_standard_mib(mib_name)
        logger.info(f"Added standard MIB: {mib_name}")

    def set_standard_mibs(self, mib_list: List[str]) -> None:
        """Set custom list of standard MIBs"""
        self.download_manager.set_standard_mibs(mib_list)
        logger.info(f"Set {len(mib_list)} standard MIBs")

    def download_dependencies(self) -> int:
        """Download all standard MIB dependencies"""
        logger.info("Starting standard MIB download...")

        downloaded_count = self.download_manager.download_all_standard_mibs()
        self.stats['dependencies_downloaded'] = downloaded_count

        logger.info(f"Downloaded {downloaded_count} standard MIBs")
        return downloaded_count

    def setup_compiler(self) -> bool:
        """Setup pysmi compiler with all sources"""
        try:
            logger.info("Setting up MIB compiler...")

            self.compiler = MibCompiler(
                SmiStarParser(),
                PySnmpCodeGen(),
                PyFileWriter(str(self.compiled_dir))
            )

            # Add MIB sources in priority order
            # 1. Vendor MIBs (highest priority)
            self.compiler.add_sources(FileReader(str(self.vendor_mib_dir)))
            logger.debug(f"Added vendor MIB source: {self.vendor_mib_dir}")

            # 2. Downloaded standard MIBs
            self.compiler.add_sources(FileReader(str(self.standard_mib_dir)))
            logger.debug(f"Added standard MIB source: {self.standard_mib_dir}")

            # 3. HTTP fallback if enabled
            if self.config.enable_http_fallback:
                try:
                    for http_source in ['https://mibs.pysnmp.com/asn1/@mib@']:
                        self.compiler.add_sources(HttpReader(http_source))
                        logger.info(f"Added HTTP MIB source: {http_source}")
                except Exception as e:
                    logger.warning(f"Could not add HTTP source: {e}")

            # Add built-in searchers
            self.compiler.add_searchers(StubSearcher(*PySnmpCodeGen.defaultMibPackages))
            logger.debug("Added built-in MIB searchers")

            logger.info("✓ MIB compiler setup completed")
            return True

        except Exception as e:
            error_msg = f"Failed to setup MIB compiler: {e}"
            logger.error(error_msg)
            raise MibCompilerSetupError("compiler_initialization", str(e))

    def validate_vendor_mibs(self) -> Dict[str, bool]:
        """Validate all vendor MIB files before compilation"""
        logger.info("Validating vendor MIB files...")

        validation_results = {}
        mib_files = list(self.vendor_mib_dir.glob("*.mib")) + list(self.vendor_mib_dir.glob("*.txt"))

        for mib_file in mib_files:
            is_valid = self.validator.validate_mib_file(mib_file)
            validation_results[mib_file.name] = is_valid

            if not is_valid:
                logger.warning(f"Validation failed for {mib_file.name}")
            else:
                logger.debug(f"✓ {mib_file.name} validation passed")

        valid_count = sum(validation_results.values())
        logger.info(f"Validation complete: {valid_count}/{len(validation_results)} files valid")

        return validation_results

    def auto_detect_mibs(self) -> List[str]:
        """Auto-detect MIB names from files in vendor directory"""
        logger.info("Auto-detecting vendor MIBs...")

        mib_files = (
                list(self.vendor_mib_dir.glob("*.mib")) +
                list(self.vendor_mib_dir.glob("*.txt"))
        )

        detected_mibs = []
        for mib_file in mib_files:
            # Try to extract MIB name from file
            try:
                with open(mib_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(1000)  # Read first 1000 chars

                # Look for MIB name in DEFINITIONS line
                import re
                match = re.search(r'^(\w+(?:-\w+)*)\s+DEFINITIONS\s*::=\s*BEGIN', content, re.MULTILINE)
                if match:
                    mib_name = match.group(1)
                    detected_mibs.append(mib_name)
                    logger.debug(f"Detected MIB: {mib_name} from {mib_file.name}")
                else:
                    # Fallback to filename without extension
                    mib_name = mib_file.stem
                    detected_mibs.append(mib_name)
                    logger.debug(f"Using filename as MIB name: {mib_name}")

            except Exception as e:
                logger.warning(f"Could not detect MIB name from {mib_file}: {e}")
                # Use filename as fallback
                detected_mibs.append(mib_file.stem)

        # Sort by dependencies if possible
        try:
            detected_mibs = self._sort_by_dependencies(detected_mibs)
        except Exception as e:
            logger.warning(f"Could not sort by dependencies: {e}")

        logger.info(f"Auto-detected {len(detected_mibs)} MIBs: {', '.join(detected_mibs)}")
        return detected_mibs

    def compile_mib_with_deps(self, mib_name: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Compile MIB with automatic dependency resolution

        Returns:
            Tuple of (success, message, details)
        """
        details = {
            'attempts': 0,
            'downloaded_deps': [],
            'compilation_time': 0,
            'output_size': 0
        }

        start_time = time.time()

        for attempt in range(self.config.max_retries):
            details['attempts'] = attempt + 1
            logger.info(f"Compiling {mib_name} (attempt {attempt + 1}/{self.config.max_retries})")

            try:
                attempt_start = time.time()
                results = self.compiler.compile(mib_name)
                compilation_time = time.time() - attempt_start
                details['compilation_time'] = compilation_time

                if mib_name in results:
                    result = results[mib_name]

                    if result == 'compiled':
                        py_file = self.compiled_dir / f"{mib_name}.py"
                        if py_file.exists():
                            size = py_file.stat().st_size
                            details['output_size'] = size

                            logger.info(f"✓ {mib_name} compiled successfully ({size:,} bytes, {compilation_time:.2f}s)")
                            return True, "compiled", details

                    elif isinstance(result, Exception):
                        error_msg = str(result)
                        logger.warning(f"Compilation error for {mib_name}: {error_msg}")

                        # Try to download missing dependency
                        missing_mib = self._extract_missing_mib(error_msg)
                        if missing_mib and missing_mib not in details['downloaded_deps']:
                            logger.info(f"Attempting to download missing dependency: {missing_mib}")
                            if self.download_manager.download_mib(missing_mib):
                                details['downloaded_deps'].append(missing_mib)
                                continue  # Retry compilation

                        return False, error_msg, details
                    else:
                        return False, str(result), details
                else:
                    return False, "no compilation result", details

            except Exception as e:
                error_msg = f"Exception during compilation: {e}"
                logger.error(f"{mib_name}: {error_msg}")

                # Check if it's a dependency issue
                if "cannot locate" in str(e).lower() or "no module named" in str(e).lower():
                    missing_mib = self._extract_missing_mib(str(e))
                    if missing_mib and missing_mib not in details['downloaded_deps']:
                        logger.info(f"Attempting to download missing dependency: {missing_mib}")
                        if self.download_manager.download_mib(missing_mib):
                            details['downloaded_deps'].append(missing_mib)
                            continue

                if attempt == self.config.max_retries - 1:  # Last attempt
                    return False, error_msg, details

        total_time = time.time() - start_time
        details['compilation_time'] = total_time
        return False, f"Failed after {self.config.max_retries} attempts", details

    def compile_vendor_mibs(self, mib_list: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
        """Compile specified vendor MIBs or auto-detect"""

        if mib_list is None:
            mib_list = self.auto_detect_mibs()

        if not mib_list:
            logger.warning("No MIBs found to compile")
            return {}

        logger.info(f"Starting compilation of {len(mib_list)} MIBs...")
        self.stats['mibs_processed'] = len(mib_list)

        results = {}
        successful_count = 0

        for i, mib_name in enumerate(mib_list, 1):
            logger.info(f"[{i}/{len(mib_list)}] Processing {mib_name}")

            success, message, details = self.compile_mib_with_deps(mib_name)

            results[mib_name] = {
                'success': success,
                'message': message,
                'details': details,
                'timestamp': datetime.now().isoformat()
            }

            if success:
                successful_count += 1
                self.stats['total_size_bytes'] += details.get('output_size', 0)
            else:
                logger.warning(f"Failed to compile {mib_name}: {message}")
                self.stats['errors'].append({
                    'mib': mib_name,
                    'error': message,
                    'details': details
                })

        self.stats['mibs_successful'] = successful_count
        self.stats['mibs_failed'] = len(mib_list) - successful_count

        logger.info(f"Compilation completed: {successful_count}/{len(mib_list)} successful")
        return results

    def get_compiled_mibs(self) -> List[Path]:
        """Get list of successfully compiled Python modules"""
        return sorted(self.compiled_dir.glob("*.py"))

    def get_compilation_stats(self) -> Dict[str, Any]:
        """Get compilation statistics"""
        stats = self.stats.copy()

        # Add computed statistics
        if stats['start_time'] and stats['end_time']:
            stats['duration'] = stats['end_time'] - stats['start_time']

        stats['success_rate'] = (
            (stats['mibs_successful'] / stats['mibs_processed'] * 100)
            if stats['mibs_processed'] > 0 else 0
        )

        # Add file information
        compiled_files = self.get_compiled_mibs()
        stats['compiled_files'] = len(compiled_files)
        stats['output_directory'] = str(self.compiled_dir)

        # Add downloaded MIB info
        downloaded_files = list(self.standard_mib_dir.glob("*.mib"))
        stats['downloaded_standard_mibs'] = len(downloaded_files)

        return stats

    def cleanup_temp_files(self) -> None:
        """Clean up temporary files if not preserving downloads"""
        if not self.config.preserve_downloads and self.work_dir.name.startswith("mib_auto_compile_"):
            try:
                shutil.rmtree(self.work_dir)
                logger.info(f"Cleaned up temporary directory: {self.work_dir}")
            except Exception as e:
                logger.warning(f"Could not clean up temporary directory: {e}")

    def run_auto_compilation(self, mib_list: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
        """
        Run complete auto-compilation process

        Args:
            mib_list: Optional list of specific MIBs to compile

        Returns:
            Dictionary of compilation results
        """
        self.stats['start_time'] = time.time()

        try:
            logger.info("=" * 70)
            logger.info("MIB AUTO-COMPILATION STARTED")
            logger.info("=" * 70)

            # Step 1: Validate vendor MIBs
            if self.config.validate_before_compile:
                validation_results = self.validate_vendor_mibs()
                failed_validations = [name for name, valid in validation_results.items() if not valid]
                if failed_validations:
                    logger.warning(f"Validation failed for: {', '.join(failed_validations)}")

            # Step 2: Download dependencies
            logger.info("Step 1: Downloading standard MIB dependencies...")
            downloaded = self.download_dependencies()
            if downloaded == 0:
                logger.warning("No standard MIBs downloaded - compilation may fail")

            # Step 3: Setup compiler
            logger.info("Step 2: Setting up MIB compiler...")
            if not self.setup_compiler():
                raise MibCompilerSetupError("Compiler setup failed")

            # Step 4: Compile vendor MIBs
            logger.info("Step 3: Compiling vendor MIBs...")
            results = self.compile_vendor_mibs(mib_list)

            # Step 5: Generate final report
            logger.info("Step 4: Generating compilation report...")
            self._generate_detailed_report(results)

            return results

        except Exception as e:
            logger.error(f"Auto-compilation failed: {e}")
            self.stats['errors'].append({
                'stage': 'auto_compilation',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })
            raise

        finally:
            self.stats['end_time'] = time.time()
            if not self.config.preserve_downloads:
                self.cleanup_temp_files()

    def _extract_missing_mib(self, error_msg: str) -> Optional[str]:
        """Extract missing MIB name from error message"""
        import re

        patterns = [
            r"cannot locate (\w+(?:-\w+)*)",
            r"No module named '(\w+(?:-\w+)*)'",
            r"ImportError.*'(\w+(?:-\w+)*)'",
            r"MIB file.*'(\w+(?:-\w+)*)'.*not found",
            r"MIB module '(\w+(?:-\w+)*)' not found"
        ]

        for pattern in patterns:
            match = re.search(pattern, error_msg, re.IGNORECASE)
            if match:
                mib_name = match.group(1)
                # Validate it looks like a MIB name
                if mib_name and mib_name.replace('-', '').replace('_', '').isalnum():
                    return mib_name

        return None

    def _sort_by_dependencies(self, mib_list: List[str]) -> List[str]:
        """Sort MIBs by dependency order (simple heuristic)"""
        # Simple sorting: SMI files first, then others
        smi_mibs = [m for m in mib_list if 'SMI' in m.upper()]
        other_mibs = [m for m in mib_list if 'SMI' not in m.upper()]

        # Further sort SMI files (base SMI first)
        base_smi = [m for m in smi_mibs if m.upper().endswith('-SMI')]
        other_smi = [m for m in smi_mibs if not m.upper().endswith('-SMI')]

        return base_smi + other_smi + other_mibs

    def _generate_detailed_report(self, results: Dict[str, Dict[str, Any]]) -> None:
        """Generate detailed compilation report"""
        logger.info("\n" + "=" * 70)
        logger.info("MIB AUTO-COMPILATION DETAILED REPORT")
        logger.info("=" * 70)

        # Summary statistics
        stats = self.get_compilation_stats()
        successful = stats['mibs_successful']
        total = stats['mibs_processed']

        logger.info(f"Compilation Summary:")
        logger.info(f"  Total MIBs: {total}")
        logger.info(f"  Successful: {successful}")
        logger.info(f"  Failed: {stats['mibs_failed']}")
        logger.info(f"  Success Rate: {stats['success_rate']:.1f}%")
        logger.info(f"  Duration: {stats.get('duration', 0):.2f} seconds")
        logger.info(f"  Dependencies Downloaded: {stats['dependencies_downloaded']}")
        logger.info(f"  Total Output Size: {stats['total_size_bytes']:,} bytes")

        # Detailed results
        logger.info(f"\nDetailed Results:")
        for mib_name, result in sorted(results.items()):
            status = "✓ PASS" if result['success'] else "✗ FAIL"
            message = result['message']
            details = result.get('details', {})

            logger.info(f"  {status:<8} {mib_name:<25} {message}")

            if details.get('downloaded_deps'):
                deps = ', '.join(details['downloaded_deps'])
                logger.info(f"           {'':<25} Downloaded deps: {deps}")

        # Show downloaded standard MIBs
        downloaded_files = list(self.standard_mib_dir.glob("*.mib"))
        if downloaded_files:
            logger.info(f"\nDownloaded Standard MIBs ({len(downloaded_files)}):")
            for mib_file in sorted(downloaded_files):
                size = mib_file.stat().st_size
                logger.info(f"  {mib_file.stem:<30} {size:>8,} bytes")

        # Show compiled outputs
        compiled_files = self.get_compiled_mibs()
        if compiled_files:
            logger.info(f"\nCompiled Output Files ({len(compiled_files)}):")
            for py_file in compiled_files:
                size = py_file.stat().st_size
                logger.info(f"  {py_file.stem:<30} {size:>8,} bytes")

        # Error summary
        if stats['errors']:
            logger.info(f"\nError Summary ({len(stats['errors'])} errors):")
            for error in stats['errors'][:5]:  # Show first 5 errors
                logger.info(f"  {error.get('mib', 'unknown')}: {error.get('error', 'unknown error')}")

            if len(stats['errors']) > 5:
                logger.info(f"  ... and {len(stats['errors']) - 5} more errors")

        logger.info(f"\nOutput Location: {self.work_dir}")
        logger.info(f"Compiled MIBs: {self.compiled_dir}")

        if successful > 0:
            logger.info(f"\n🎉 SUCCESS! {successful} MIB(s) compiled successfully!")
            logger.info(f"Use the compiled Python modules from: {self.compiled_dir}")
        else:
            logger.info(f"\nFAILED: No MIBs compiled successfully.")
            logger.info(f"Check error messages above for troubleshooting.")

        logger.info("=" * 70)