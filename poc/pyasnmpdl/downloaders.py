
# ============================================================================
# mib_auto_downloader/downloaders.py
"""
MIB download management
"""

import requests
import time
from pathlib import Path
from typing import List
import logging

logger = logging.getLogger(__name__)


class MibDownloadManager:
    """Manages downloading MIBs from various sources"""

    def __init__(self, download_directory: Path, timeout: int = 10):
        self.download_dir = download_directory
        self.timeout = timeout

        # Default standard MIBs
        self.standard_mibs = [
            'SNMPv2-SMI', 'SNMPv2-TC', 'SNMPv2-CONF', 'SNMPv2-MIB',
            'RFC1155-SMI', 'RFC1213-MIB', 'IF-MIB', 'IP-MIB',
            'TCP-MIB', 'UDP-MIB', 'IANAifType-MIB',
            'IANA-ADDRESS-FAMILY-NUMBERS-MIB', 'IANA-LANGUAGE-MIB',
            'HOST-RESOURCES-MIB', 'ENTITY-MIB', 'DISMAN-EVENT-MIB'
        ]

        # Default download sources
        self.sources = [
            'https://mibs.pysnmp.com/asn1/',
            'https://www.circitor.fr/Mibs/Mib/',
            'https://raw.githubusercontent.com/librenms/librenms/master/mibs/'
        ]

    def add_source(self, url: str):
        """Add custom download source"""
        if url not in self.sources:
            self.sources.append(url)

    def add_standard_mib(self, mib_name: str):
        """Add MIB to standard download list"""
        if mib_name not in self.standard_mibs:
            self.standard_mibs.append(mib_name)

    def set_standard_mibs(self, mib_list: List[str]):
        """Set custom standard MIB list"""
        self.standard_mibs = mib_list

    def download_mib(self, mib_name: str) -> bool:
        """Download a single MIB"""
        logger.info(f"Downloading {mib_name}...")

        for base_url in self.sources:
            for extension in ['.mib', '.txt', '']:
                url = f"{base_url}{mib_name}{extension}"

                try:
                    logger.debug(f"Trying {url}")
                    response = requests.get(url, timeout=self.timeout)

                    if response.status_code == 200:
                        content = response.text

                        # Validate content
                        if 'DEFINITIONS ::= BEGIN' in content:
                            mib_file = self.download_dir / f"{mib_name}.mib"
                            with open(mib_file, 'w', encoding='utf-8') as f:
                                f.write(content)

                            logger.info(f"✓ Downloaded {mib_name} from {base_url}")
                            return True

                except requests.RequestException as e:
                    logger.debug(f"Failed to download from {url}: {e}")
                    continue

                time.sleep(0.1)  # Rate limiting

        logger.warning(f"✗ Could not download {mib_name}")
        return False

    def download_all_standard_mibs(self) -> int:
        """Download all standard MIBs"""
        logger.info("Downloading standard MIBs...")

        success_count = 0
        for mib_name in self.standard_mibs:
            if self.download_mib(mib_name):
                success_count += 1

        logger.info(f"Downloaded {success_count}/{len(self.standard_mibs)} standard MIBs")
        return success_count

