"""
Configuration management for MIB Auto Compiler
"""

import os
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
import logging
from dataclasses import dataclass, field, asdict
import json

logger = logging.getLogger(__name__)

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    logger.debug("PyYAML not available - YAML config files not supported")


@dataclass
class CompilerConfig:
    """Configuration class for MIB Auto Compiler"""

    # Core settings
    output_directory: Optional[str] = None
    max_retries: int = 3
    download_timeout: int = 10
    enable_http_fallback: bool = True
    preserve_downloads: bool = True
    validate_before_compile: bool = True

    # MIB sources (download URLs)
    mib_sources: List[str] = field(default_factory=lambda: [
        'https://mibs.pysnmp.com/asn1/',
        'https://www.circitor.fr/Mibs/Mib/',
        'https://raw.githubusercontent.com/librenms/librenms/master/mibs/',
        'https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/',
        'https://raw.githubusercontent.com/netsnmp/net-snmp/master/mibs/'
    ])

    # Standard MIBs to download
    standard_mibs: List[str] = field(default_factory=lambda: [
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
        'ENTITY-STATE-MIB',
        'DISMAN-EVENT-MIB',
        'DISMAN-SCHEDULE-MIB',
        'NOTIFICATION-LOG-MIB',

        # Bridge and switch MIBs
        'BRIDGE-MIB',
        'P-BRIDGE-MIB',
        'Q-BRIDGE-MIB',

        # RADIUS and authentication
        'RADIUS-AUTH-CLIENT-MIB',
        'RADIUS-ACC-CLIENT-MIB',

        # Power and environment
        'POWER-ETHERNET-MIB',
        'EtherLike-MIB',

        # SNMP framework
        'SNMP-FRAMEWORK-MIB',
        'SNMP-MPD-MIB',
        'SNMP-TARGET-MIB',
        'SNMP-NOTIFICATION-MIB',
        'SNMP-USER-BASED-SM-MIB',
        'SNMP-VIEW-BASED-ACM-MIB'
    ])

    # Vendor-specific settings
    vendor_specific: Dict[str, Any] = field(default_factory=dict)

    # Logging configuration
    log_level: str = "INFO"
    log_to_file: bool = False
    log_file_path: Optional[str] = None

    # Output format settings
    generate_reports: bool = True
    report_formats: List[str] = field(default_factory=lambda: ['text'])
    include_statistics: bool = True

    def __post_init__(self):
        """Validate configuration after initialization"""
        self._validate_config()

    def _validate_config(self) -> None:
        """Validate configuration values"""
        # Validate retry count
        if self.max_retries < 1:
            raise ValueError("max_retries must be at least 1")

        # Validate timeout
        if self.download_timeout < 1:
            raise ValueError("download_timeout must be at least 1 second")

        # Validate log level
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self.log_level.upper() not in valid_log_levels:
            raise ValueError(f"log_level must be one of: {valid_log_levels}")

        # Validate report formats
        valid_formats = ['text', 'json', 'html', 'yaml']
        for fmt in self.report_formats:
            if fmt not in valid_formats:
                raise ValueError(f"Invalid report format '{fmt}'. Valid formats: {valid_formats}")

        # Validate MIB sources
        for source in self.mib_sources:
            if not source.startswith(('http://', 'https://')):
                logger.warning(f"MIB source may be invalid (not HTTP/HTTPS): {source}")

    @classmethod
    def load_from_file(cls, config_path: Union[str, Path]) -> 'CompilerConfig':
        """Load configuration from file (JSON or YAML)"""
        config_path = Path(config_path)

        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                if config_path.suffix.lower() in ['.yaml', '.yml']:
                    if not HAS_YAML:
                        raise ImportError("PyYAML is required for YAML config files. Install with: pip install PyYAML")
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)

            # Filter out None values and unknown fields
            if data is None:
                data = {}

            # Get valid field names from dataclass
            valid_fields = {field.name for field in cls.__dataclass_fields__.values()}
            filtered_data = {k: v for k, v in data.items() if k in valid_fields and v is not None}

            logger.info(f"Loaded configuration from {config_path}")
            return cls(**filtered_data)

        except (json.JSONDecodeError, yaml.YAMLError) as e:
            raise ValueError(f"Invalid configuration file format: {e}")
        except Exception as e:
            raise RuntimeError(f"Failed to load configuration: {e}")

    def save_to_file(self, config_path: Union[str, Path], format_type: Optional[str] = None) -> None:
        """Save configuration to file"""
        config_path = Path(config_path)

        # Determine format from extension if not specified
        if format_type is None:
            if config_path.suffix.lower() in ['.yaml', '.yml']:
                format_type = 'yaml'
            else:
                format_type = 'json'

        # Convert to dictionary
        config_dict = asdict(self)

        # Create parent directory if it doesn't exist
        config_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                if format_type == 'yaml':
                    if not HAS_YAML:
                        raise ImportError("PyYAML is required for YAML output. Install with: pip install PyYAML")
                    yaml.dump(config_dict, f, default_flow_style=False, indent=2)
                else:
                    json.dump(config_dict, f, indent=2, ensure_ascii=False)

            logger.info(f"Configuration saved to {config_path}")

        except Exception as e:
            raise RuntimeError(f"Failed to save configuration: {e}")

    @classmethod
    def create_template(cls, template_type: str = 'basic') -> 'CompilerConfig':
        """Create a configuration template"""

        if template_type == 'basic':
            return cls(
                output_directory=None,
                max_retries=3,
                download_timeout=10,
                preserve_downloads=True,
                log_level="INFO",
                report_formats=['text']
            )

        elif template_type == 'advanced':
            return cls(
                output_directory="./compiled_mibs",
                max_retries=5,
                download_timeout=15,
                enable_http_fallback=True,
                preserve_downloads=True,
                validate_before_compile=True,
                log_level="DEBUG",
                log_to_file=True,
                log_file_path="./logs/mib_compiler.log",
                generate_reports=True,
                report_formats=['text', 'json'],
                include_statistics=True,
                vendor_specific={
                    "cisco": {
                        "additional_sources": ["https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/"],
                        "priority_mibs": ["CISCO-SMI", "CISCO-TC"]
                    },
                    "juniper": {
                        "additional_sources": ["https://raw.githubusercontent.com/Juniper/yang/master/"],
                        "priority_mibs": ["JUNIPER-SMI"]
                    }
                }
            )

        elif template_type == 'enterprise':
            config = cls.create_template('advanced')

            # Add more enterprise features
            config.mib_sources.extend([
                'https://raw.githubusercontent.com/SNMP-RESEARCH/mibs/master/',
                'https://raw.githubusercontent.com/cisco/cisco-mibs/main/v1/',
                'https://raw.githubusercontent.com/netsnmp/net-snmp/master/mibs/',
                'https://www.net-snmp.org/docs/mibs/'
            ])

            # Add more standard MIBs for enterprise environments
            config.standard_mibs.extend([
                'CISCO-SMI',
                'CISCO-TC',
                'JUNIPER-SMI',
                'ARISTA-SMI-MIB',
                'DELL-VENDOR-MIB',
                'HP-ICF-OID',
                'HUAWEI-MIB',
                'FORTINET-CORE-MIB',
                'PALO-ALTO-GLOBAL-REG'
            ])

            config.vendor_specific.update({
                "arista": {
                    "additional_sources": ["https://raw.githubusercontent.com/arista-eos/mibs/master/"],
                    "priority_mibs": ["ARISTA-SMI-MIB"]
                },
                "fortinet": {
                    "additional_sources": ["https://docs.fortinet.com/"],
                    "priority_mibs": ["FORTINET-CORE-MIB"]
                },
                "palo_alto": {
                    "priority_mibs": ["PALO-ALTO-GLOBAL-REG"]
                }
            })

            return config

        else:
            raise ValueError(f"Unknown template type: {template_type}")

    def merge_with(self, other: 'CompilerConfig') -> 'CompilerConfig':
        """Merge this configuration with another, with other taking precedence"""

        # Convert both to dictionaries
        self_dict = asdict(self)
        other_dict = asdict(other)

        # Merge dictionaries
        merged = self_dict.copy()

        for key, value in other_dict.items():
            if value is not None:
                if key in ['mib_sources', 'standard_mibs', 'report_formats']:
                    # For lists, combine and deduplicate
                    if isinstance(value, list) and isinstance(merged.get(key), list):
                        merged[key] = list(set(merged[key] + value))
                    else:
                        merged[key] = value
                elif key == 'vendor_specific':
                    # For dictionaries, deep merge
                    if isinstance(value, dict) and isinstance(merged.get(key), dict):
                        merged[key] = {**merged[key], **value}
                    else:
                        merged[key] = value
                else:
                    merged[key] = value

        return CompilerConfig(**merged)

    def get_vendor_config(self, vendor_name: str) -> Dict[str, Any]:
        """Get vendor-specific configuration"""
        return self.vendor_specific.get(vendor_name.lower(), {})

    def add_vendor_config(self, vendor_name: str, config: Dict[str, Any]) -> None:
        """Add or update vendor-specific configuration"""
        self.vendor_specific[vendor_name.lower()] = config

    def setup_logging(self) -> None:
        """Setup logging based on configuration"""
        # Convert string level to logging constant
        log_level = getattr(logging, self.log_level.upper(), logging.INFO)

        # Setup handlers
        handlers = []

        # Console handler (always present)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        handlers.append(console_handler)

        # File handler (if enabled)
        if self.log_to_file and self.log_file_path:
            log_path = Path(self.log_file_path)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(log_path)
            file_handler.setLevel(log_level)
            handlers.append(file_handler)

        # Configure root logger
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=handlers,
            force=True  # Override existing configuration
        )

        logger.info(f"Logging configured: level={self.log_level}, file={self.log_to_file}")

    def validate_environment(self) -> List[str]:
        """Validate the environment and return list of issues"""
        issues = []

        # Check if output directory is writable
        if self.output_directory:
            output_path = Path(self.output_directory)
            try:
                output_path.mkdir(parents=True, exist_ok=True)
                # Try to create a test file
                test_file = output_path / ".test_write"
                test_file.touch()
                test_file.unlink()
            except Exception as e:
                issues.append(f"Output directory not writable: {e}")

        # Check if log directory is writable
        if self.log_to_file and self.log_file_path:
            log_path = Path(self.log_file_path)
            try:
                log_path.parent.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                issues.append(f"Log directory not writable: {e}")

        # Check network connectivity for MIB sources
        try:
            import requests
            for source in self.mib_sources[:2]:  # Check first 2 sources
                try:
                    response = requests.head(source, timeout=5)
                    if response.status_code >= 400:
                        issues.append(f"MIB source may be unavailable: {source}")
                except requests.RequestException:
                    issues.append(f"Cannot reach MIB source: {source}")
        except ImportError:
            issues.append("requests library not available - cannot check MIB sources")

        return issues

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return asdict(self)

    def __str__(self) -> str:
        """String representation of configuration"""
        return f"CompilerConfig(output_dir={self.output_directory}, retries={self.max_retries}, timeout={self.download_timeout})"

    def __repr__(self) -> str:
        """Detailed string representation"""
        return f"CompilerConfig({self.to_dict()})"


def load_config_from_env() -> CompilerConfig:
    """Load configuration from environment variables"""
    env_config = {}

    # Map environment variables to config fields
    env_mappings = {
        'MIB_COMPILER_OUTPUT_DIR': 'output_directory',
        'MIB_COMPILER_MAX_RETRIES': ('max_retries', int),
        'MIB_COMPILER_TIMEOUT': ('download_timeout', int),
        'MIB_COMPILER_HTTP_FALLBACK': ('enable_http_fallback', lambda x: x.lower() in ['true', '1', 'yes']),
        'MIB_COMPILER_PRESERVE_DOWNLOADS': ('preserve_downloads', lambda x: x.lower() in ['true', '1', 'yes']),
        'MIB_COMPILER_VALIDATE': ('validate_before_compile', lambda x: x.lower() in ['true', '1', 'yes']),
        'MIB_COMPILER_LOG_LEVEL': 'log_level',
        'MIB_COMPILER_LOG_FILE': ('log_to_file', lambda x: x.lower() in ['true', '1', 'yes']),
        'MIB_COMPILER_LOG_PATH': 'log_file_path',
    }

    for env_var, config_field in env_mappings.items():
        env_value = os.getenv(env_var)
        if env_value is not None:
            if isinstance(config_field, tuple):
                field_name, converter = config_field
                try:
                    env_config[field_name] = converter(env_value)
                except (ValueError, TypeError) as e:
                    logger.warning(f"Invalid environment variable {env_var}={env_value}: {e}")
            else:
                env_config[config_field] = env_value

    # Handle list environment variables (comma-separated)
    mib_sources = os.getenv('MIB_COMPILER_SOURCES')
    if mib_sources:
        env_config['mib_sources'] = [s.strip() for s in mib_sources.split(',') if s.strip()]

    standard_mibs = os.getenv('MIB_COMPILER_STANDARD_MIBS')
    if standard_mibs:
        env_config['standard_mibs'] = [s.strip() for s in standard_mibs.split(',') if s.strip()]

    logger.debug(f"Loaded {len(env_config)} configuration values from environment")
    return CompilerConfig(**env_config)


def get_default_config_paths() -> List[Path]:
    """Get list of default configuration file paths to check"""
    paths = []

    # Current directory
    for filename in ['mib-compiler.yaml', 'mib-compiler.yml', 'mib-compiler.json', '.mib-compiler.yaml']:
        paths.append(Path.cwd() / filename)

    # User home directory
    home = Path.home()
    for filename in ['.mib-compiler.yaml', '.mib-compiler.yml', '.mib-compiler.json']:
        paths.append(home / filename)

    # System configuration directories
    if os.name != 'nt':  # Unix-like systems
        for config_dir in ['/etc/mib-compiler', '/usr/local/etc/mib-compiler']:
            for filename in ['config.yaml', 'config.yml', 'config.json']:
                paths.append(Path(config_dir) / filename)

    return paths


def find_config_file() -> Optional[Path]:
    """Find the first existing configuration file in default locations"""
    for config_path in get_default_config_paths():
        if config_path.exists():
            logger.info(f"Found configuration file: {config_path}")
            return config_path

    logger.debug("No configuration file found in default locations")
    return None


def create_default_config() -> CompilerConfig:
    """Create default configuration with environment variable overrides"""
    # Start with basic template
    config = CompilerConfig.create_template('basic')

    # Load environment overrides
    env_config = load_config_from_env()

    # Merge configurations
    if any(asdict(env_config).values()):
        config = config.merge_with(env_config)
        logger.info("Applied environment variable overrides to configuration")

    return config