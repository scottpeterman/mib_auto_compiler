
#!/usr/bin/env python3
"""
MIB Auto-Downloader and Compiler for Prisma SD-WAN MIBs
Automatically downloads standard MIB dependencies and compiles vendor MIBs
"""

import os
import tempfile
import requests
from pathlib import Path
import logging
import time

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
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
    logger.error(f"Missing pysmi dependency: {e}")
    logger.error("Install with: pip install pysmi")
    exit(1)


class MibAutoDownloader:
    """Automatically downloads and compiles MIB dependencies"""

    def __init__(self, vendor_mib_directory: str):
        self.vendor_mib_dir = Path(vendor_mib_directory)
        self.work_dir = Path(tempfile.mkdtemp(prefix="mib_auto_compile_"))

        # Create subdirectories
        self.standard_mib_dir = self.work_dir / "standard_mibs"
        self.standard_mib_dir.mkdir(exist_ok=True)

        self.compiled_dir = self.work_dir / "compiled"
        self.compiled_dir.mkdir(exist_ok=True)

        logger.info(f"Working directory: {self.work_dir}")

        # Common standard MIBs that vendor MIBs typically depend on
        self.standard_mibs = [
            # Core SNMPv2 MIBs
            'SNMPv2-SMI',
            'SNMPv2-TC',
            'SNMPv2-CONF',
            'SNMPv2-MIB',

            # Standard MIBs
            'RFC1155-SMI',
            'RFC1213-MIB',
            'IF-MIB',
            'IP-MIB',
            'TCP-MIB',
            'UDP-MIB',

            # IANA MIBs
            'IANAifType-MIB',
            'IANA-ADDRESS-FAMILY-NUMBERS-MIB',
            'IANA-LANGUAGE-MIB',

            # Common enterprise MIBs
            'HOST-RESOURCES-MIB',
            'ENTITY-MIB',
            'DISMAN-EVENT-MIB'
        ]

        # MIB download sources
        self.mib_sources = [
            'https://mibs.pysnmp.com/asn1/',
            'https://www.circitor.fr/Mibs/Mib/',
            'https://raw.githubusercontent.com/librenms/librenms/master/mibs/'
        ]

    def download_standard_mib(self, mib_name: str) -> bool:
        """Download a standard MIB from online sources"""
        logger.info(f"Downloading {mib_name}...")

        for base_url in self.mib_sources:
            for extension in ['.mib', '.txt', '']:
                url = f"{base_url}{mib_name}{extension}"

                try:
                    logger.debug(f"Trying {url}")
                    response = requests.get(url, timeout=10)

                    if response.status_code == 200:
                        content = response.text

                        # Basic validation - check if it looks like a MIB
                        if 'DEFINITIONS ::= BEGIN' in content:
                            mib_file = self.standard_mib_dir / f"{mib_name}.mib"
                            with open(mib_file, 'w', encoding='utf-8') as f:
                                f.write(content)

                            logger.info(f"✓ Downloaded {mib_name} from {base_url}")
                            return True

                except requests.RequestException as e:
                    logger.debug(f"Failed to download from {url}: {e}")
                    continue

                # Small delay between requests
                time.sleep(0.1)

        logger.warning(f"✗ Could not download {mib_name}")
        return False

    def download_all_standard_mibs(self):
        """Download all standard MIBs"""
        logger.info("Downloading standard MIBs...")

        success_count = 0
        for mib_name in self.standard_mibs:
            if self.download_standard_mib(mib_name):
                success_count += 1

        logger.info(f"Downloaded {success_count}/{len(self.standard_mibs)} standard MIBs")
        return success_count

    def setup_compiler(self):
        """Setup compiler with all MIB sources"""
        try:
            self.compiler = MibCompiler(
                SmiStarParser(),
                PySnmpCodeGen(),
                PyFileWriter(str(self.compiled_dir))
            )

            # Add vendor MIB directory
            self.compiler.add_sources(FileReader(str(self.vendor_mib_dir)))

            # Add downloaded standard MIBs
            self.compiler.add_sources(FileReader(str(self.standard_mib_dir)))

            # Add HTTP source as backup
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

    def compile_mib_with_deps(self, mib_name: str, max_retries: int = 3):
        """Compile a MIB, downloading dependencies as needed"""

        for attempt in range(max_retries):
            logger.info(f"Compiling {mib_name} (attempt {attempt + 1}/{max_retries})")

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

                        # Try to identify missing dependencies
                        if "No module named" in error_msg or "cannot locate" in error_msg.lower():
                            missing_mib = self.extract_missing_mib(error_msg)
                            if missing_mib and missing_mib not in self.standard_mibs:
                                logger.info(f"Attempting to download missing dependency: {missing_mib}")
                                if self.download_standard_mib(missing_mib):
                                    continue  # Retry compilation

                        return False, error_msg
                    else:
                        logger.warning(f"Unexpected compilation result for {mib_name}: {result}")
                        return False, str(result)
                else:
                    logger.warning(f"No compilation result for {mib_name}")
                    return False, "no result"

            except Exception as e:
                logger.error(f"Exception during compilation of {mib_name}: {e}")
                return False, str(e)

        return False, f"Failed after {max_retries} attempts"

    def extract_missing_mib(self, error_msg: str) -> str:
        """Extract missing MIB name from error message"""
        # This is a heuristic approach - error messages vary
        import re

        # Look for patterns like "cannot locate MIB-NAME"
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

    def compile_vendor_mibs(self):
        """Compile all vendor MIBs"""
        logger.info("Compiling Prisma SD-WAN MIBs...")

        # Vendor MIBs in dependency order
        vendor_mibs = [
            "CLOUDGENIX-SMI",
            "CGX-MODELS-MIB",
            "CGX-ENV-MIB",
            "CGX-STATUS-MIB",
            "CGX-EVENTS-MIB"
        ]

        results = {}

        for mib_name in vendor_mibs:
            success, message = self.compile_mib_with_deps(mib_name)
            results[mib_name] = {'success': success, 'message': message}

            if not success:
                logger.warning(f"Failed to compile {mib_name}: {message}")

        return results

    def generate_final_report(self, results):
        """Generate final compilation report"""
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

        # Show downloaded dependencies
        standard_files = list(self.standard_mib_dir.glob("*.mib"))
        if standard_files:
            logger.info(f"\nDownloaded Standard MIBs ({len(standard_files)}):")
            for mib_file in sorted(standard_files):
                size = mib_file.stat().st_size
                logger.info(f"  {mib_file.stem:<25} {size:>8} bytes")

        # Show compiled outputs
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

    def run_auto_compilation(self):
        """Run the complete auto-compilation process"""
        logger.info("Starting MIB auto-compilation with dependency download...")

        # Step 1: Download standard MIBs
        downloaded = self.download_all_standard_mibs()
        if downloaded == 0:
            logger.warning("No standard MIBs downloaded - compilation may fail")

        # Step 2: Setup compiler
        if not self.setup_compiler():
            logger.error("Compiler setup failed")
            return False

        # Step 3: Compile vendor MIBs
        results = self.compile_vendor_mibs()

        # Step 4: Generate report
        self.generate_final_report(results)

        return any(r['success'] for r in results.values())


def main():
    """Main function"""
    mib_directory = r"C:\Users\speterman\PycharmProjects\kmibs\prisma-sd-wan-mib-files"

    if not os.path.exists(mib_directory):
        logger.error(f"MIB directory not found: {mib_directory}")
        return 1

    downloader = MibAutoDownloader(mib_directory)

    try:
        success = downloader.run_auto_compilation()
        return 0 if success else 1
    except KeyboardInterrupt:
        logger.info("Process interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Auto-compilation failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())