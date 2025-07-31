"""
Basic tests for MIB Auto Compiler
"""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import responses

from mib_auto_compiler import (
    MibAutoCompiler,
    CompilerConfig,
    MibDownloadManager,
    MibValidator,
    MibAutoCompilerError,
    MibDownloadError,
    MibCompilationError,
    extract_mib_dependencies,
    extract_mib_info,
    analyze_mib_directory
)


class TestCompilerConfig:
    """Test CompilerConfig class"""

    def test_default_config(self):
        """Test default configuration creation"""
        config = CompilerConfig()

        assert config.max_retries == 3
        assert config.download_timeout == 10
        assert config.enable_http_fallback is True
        assert config.preserve_downloads is True
        assert len(config.mib_sources) > 0
        assert len(config.standard_mibs) > 0

    def test_config_validation(self):
        """Test configuration validation"""
        # Valid config
        config = CompilerConfig(max_retries=5, download_timeout=15)
        assert config.max_retries == 5

        # Invalid retry count
        with pytest.raises(ValueError, match="max_retries must be at least 1"):
            CompilerConfig(max_retries=0)

        # Invalid timeout
        with pytest.raises(ValueError, match="download_timeout must be at least 1"):
            CompilerConfig(download_timeout=0)

    def test_template_creation(self):
        """Test configuration template creation"""
        basic = CompilerConfig.create_template('basic')
        assert basic.max_retries == 3

        advanced = CompilerConfig.create_template('advanced')
        assert advanced.max_retries == 5
        assert advanced.log_to_file is True

        enterprise = CompilerConfig.create_template('enterprise')
        assert len(enterprise.mib_sources) > len(basic.mib_sources)
        assert 'cisco' in enterprise.vendor_specific

    def test_config_merge(self):
        """Test configuration merging"""
        config1 = CompilerConfig(max_retries=3, download_timeout=10)
        config2 = CompilerConfig(max_retries=5, preserve_downloads=False)

        merged = config1.merge_with(config2)
        assert merged.max_retries == 5  # From config2
        assert merged.download_timeout == 10  # From config1
        assert merged.preserve_downloads is False  # From config2

    def test_config_file_operations(self):
        """Test configuration file save/load"""
        config = CompilerConfig(max_retries=5, download_timeout=15)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_path = Path(f.name)

        try:
            # Save configuration
            config.save_to_file(config_path, 'json')
            assert config_path.exists()

            # Load configuration
            loaded_config = CompilerConfig.load_from_file(config_path)
            assert loaded_config.max_retries == 5
            assert loaded_config.download_timeout == 15

        finally:
            if config_path.exists():
                config_path.unlink()


class TestMibValidator:
    """Test MibValidator class"""

    @pytest.fixture
    def temp_mib_file(self):
        """Create a temporary MIB file for testing"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.mib', delete=False) as f:
            f.write("""TEST-MIB DEFINITIONS ::= BEGIN

IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Integer32
        FROM SNMPv2-SMI;

testMib MODULE-IDENTITY
    LAST-UPDATED "202401010000Z"
    ORGANIZATION "Test Organization"
    CONTACT-INFO "test@example.com"
    DESCRIPTION "A test MIB"
    ::= { 1 3 6 1 4 1 99999 1 }

testObject OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "A test object"
    ::= { testMib 1 }

END""")
            return Path(f.name)

    @pytest.fixture
    def invalid_mib_file(self):
        """Create an invalid MIB file for testing"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.mib', delete=False) as f:
            f.write("""INVALID-MIB
This is not a valid MIB file
Missing DEFINITIONS ::= BEGIN
""")
            return Path(f.name)

    def test_validate_valid_mib(self, temp_mib_file):
        """Test validation of a valid MIB file"""
        validator = MibValidator()

        try:
            result = validator.validate_mib_file(temp_mib_file)
            assert result is True
        finally:
            temp_mib_file.unlink()

    def test_validate_invalid_mib(self, invalid_mib_file):
        """Test validation of an invalid MIB file"""
        validator = MibValidator()

        try:
            result = validator.validate_mib_file(invalid_mib_file)
            assert result is False
        finally:
            invalid_mib_file.unlink()

    def test_detailed_syntax_check(self, temp_mib_file):
        """Test detailed syntax checking"""
        validator = MibValidator()

        try:
            report = validator.check_mib_syntax(temp_mib_file)

            assert 'file' in report
            assert 'valid' in report
            assert 'statistics' in report
            assert 'info' in report

            assert report['valid'] is True
            assert report['statistics']['line_count'] > 0
            assert report['info']['name'] == 'TEST-MIB'

        finally:
            temp_mib_file.unlink()


class TestMibDownloadManager:
    """Test MibDownloadManager class"""

    @pytest.fixture
    def temp_download_dir(self):
        """Create temporary download directory"""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield Path(temp_dir)

    def test_initialization(self, temp_download_dir):
        """Test download manager initialization"""
        manager = MibDownloadManager(temp_download_dir)

        assert manager.download_dir == temp_download_dir
        assert len(manager.standard_mibs) > 0
        assert len(manager.sources) > 0

    def test_add_source(self, temp_download_dir):
        """Test adding custom MIB sources"""
        manager = MibDownloadManager(temp_download_dir)
        initial_count = len(manager.sources)

        manager.add_source("https://example.com/mibs/")
        assert len(manager.sources) == initial_count + 1
        assert "https://example.com/mibs/" in manager.sources

    def test_add_standard_mib(self, temp_download_dir):
        """Test adding standard MIBs"""
        manager = MibDownloadManager(temp_download_dir)
        initial_count = len(manager.standard_mibs)

        manager.add_standard_mib("CUSTOM-MIB")
        assert len(manager.standard_mibs) == initial_count + 1
        assert "CUSTOM-MIB" in manager.standard_mibs

    @responses.activate
    def test_successful_download(self, temp_download_dir):
        """Test successful MIB download"""
        # Mock successful HTTP response
        responses.add(
            responses.GET,
            "https://example.com/mibs/TEST-MIB.mib",
            body="""TEST-MIB DEFINITIONS ::= BEGIN
END""",
            status=200
        )

        manager = MibDownloadManager(temp_download_dir)
        manager.sources = ["https://example.com/mibs/"]

        result = manager.download_mib("TEST-MIB")
        assert result is True

        downloaded_file = temp_download_dir / "TEST-MIB.mib"
        assert downloaded_file.exists()
        assert "DEFINITIONS ::= BEGIN" in downloaded_file.read_text()

    @responses.activate
    def test_failed_download(self, temp_download_dir):
        """Test failed MIB download"""
        # Mock failed HTTP response
        responses.add(
            responses.GET,
            "https://example.com/mibs/NONEXISTENT-MIB.mib",
            status=404
        )

        manager = MibDownloadManager(temp_download_dir)
        manager.sources = ["https://example.com/mibs/"]

        result = manager.download_mib("NONEXISTENT-MIB")
        assert result is False


class TestMibAutoCompiler:
    """Test MibAutoCompiler class"""

    @pytest.fixture
    def temp_vendor_dir(self):
        """Create temporary vendor MIB directory with test files"""
        with tempfile.TemporaryDirectory() as temp_dir:
            vendor_dir = Path(temp_dir)

            # Create a test MIB file
            test_mib = vendor_dir / "TEST-VENDOR-MIB.mib"
            test_mib.write_text("""TEST-VENDOR-MIB DEFINITIONS ::= BEGIN

IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Integer32
        FROM SNMPv2-SMI;

testVendorMib MODULE-IDENTITY
    LAST-UPDATED "202401010000Z"
    ORGANIZATION "Test Vendor"
    CONTACT-INFO "vendor@example.com"
    DESCRIPTION "A test vendor MIB"
    ::= { 1 3 6 1 4 1 99999 2 }

vendorObject OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "A vendor test object"
    ::= { testVendorMib 1 }

END""")

            yield vendor_dir

    def test_initialization(self, temp_vendor_dir):
        """Test MibAutoCompiler initialization"""
        compiler = MibAutoCompiler(str(temp_vendor_dir))

        assert compiler.vendor_mib_dir == temp_vendor_dir
        assert compiler.work_dir.exists()
        assert compiler.standard_mib_dir.exists()
        assert compiler.compiled_dir.exists()

    def test_initialization_invalid_directory(self):
        """Test initialization with invalid directory"""
        with pytest.raises(MibAutoCompilerError, match="Vendor MIB directory not found"):
            MibAutoCompiler("/nonexistent/directory")

    def test_auto_detect_mibs(self, temp_vendor_dir):
        """Test automatic MIB detection"""
        compiler = MibAutoCompiler(str(temp_vendor_dir))

        detected_mibs = compiler.auto_detect_mibs()
        assert len(detected_mibs) > 0
        assert "TEST-VENDOR-MIB" in detected_mibs

    def test_validate_vendor_mibs(self, temp_vendor_dir):
        """Test vendor MIB validation"""
        compiler = MibAutoCompiler(str(temp_vendor_dir))

        validation_results = compiler.validate_vendor_mibs()
        assert len(validation_results) > 0
        assert "TEST-VENDOR-MIB.mib" in validation_results
        assert validation_results["TEST-VENDOR-MIB.mib"] is True

    @patch('mib_auto_compiler.core.MibCompiler')
    def test_setup_compiler(self, mock_compiler_class, temp_vendor_dir):
        """Test compiler setup"""
        mock_compiler = Mock()
        mock_compiler_class.return_value = mock_compiler

        compiler = MibAutoCompiler(str(temp_vendor_dir))
        result = compiler.setup_compiler()

        assert result is True
        assert compiler.compiler == mock_compiler
        mock_compiler.add_sources.assert_called()
        mock_compiler.add_searchers.assert_called()

    def test_get_compilation_stats(self, temp_vendor_dir):
        """Test compilation statistics"""
        compiler = MibAutoCompiler(str(temp_vendor_dir))

        stats = compiler.get_compilation_stats()

        assert 'mibs_processed' in stats
        assert 'mibs_successful' in stats
        assert 'mibs_failed' in stats
        assert 'dependencies_downloaded' in stats
        assert 'output_directory' in stats


class TestUtilityFunctions:
    """Test utility functions"""

    @pytest.fixture
    def sample_mib_content(self):
        """Sample MIB content for testing"""
        return """SAMPLE-MIB DEFINITIONS ::= BEGIN

IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Integer32
        FROM SNMPv2-SMI
    DisplayString
        FROM SNMPv2-TC;

sampleMib MODULE-IDENTITY
    LAST-UPDATED "202401010000Z"
    ORGANIZATION "Sample Organization"
    CONTACT-INFO "sample@example.com"
    DESCRIPTION "A sample MIB for testing"
    ::= { 1 3 6 1 4 1 99999 3 }

sampleObject OBJECT-TYPE
    SYNTAX DisplayString
    MAX-ACCESS read-write
    STATUS current
    DESCRIPTION "A sample object"
    ::= { sampleMib 1 }

END"""

    @pytest.fixture
    def temp_mib_file(self, sample_mib_content):
        """Create temporary MIB file with sample content"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.mib', delete=False) as f:
            f.write(sample_mib_content)
            return Path(f.name)

    def test_extract_mib_dependencies(self, temp_mib_file):
        """Test MIB dependency extraction"""
        try:
            dependencies = extract_mib_dependencies(temp_mib_file)

            assert isinstance(dependencies, set)
            assert 'SNMPv2-SMI' in dependencies
            assert 'SNMPv2-TC' in dependencies
        finally:
            temp_mib_file.unlink()

    def test_extract_mib_info(self, temp_mib_file):
        """Test comprehensive MIB information extraction"""
        try:
            info = extract_mib_info(temp_mib_file)

            assert info['name'] == 'SAMPLE-MIB'
            assert 'SNMPv2-SMI' in info['dependencies']
            assert 'SNMPv2-TC' in info['dependencies']
            assert len(info['object_types']) > 0
            assert info['size'] > 0
            assert info['lines'] > 0

            # Check object type details
            obj = info['object_types'][0]
            assert obj['name'] == 'sampleObject'
            assert obj['syntax'] == 'DisplayString'
            assert obj['access'] == 'read-write'
            assert obj['status'] == 'current'

        finally:
            temp_mib_file.unlink()

    def test_analyze_mib_directory(self, temp_mib_file):
        """Test MIB directory analysis"""
        try:
            mib_dir = temp_mib_file.parent
            analysis = analyze_mib_directory(mib_dir)

            assert 'summary' in analysis
            assert 'mibs' in analysis
            assert 'statistics' in analysis

            summary = analysis['summary']
            assert summary['total_files'] >= 1
            assert summary['total_size'] > 0

        finally:
            temp_mib_file.unlink()


class TestExceptions:
    """Test custom exceptions"""

    def test_mib_auto_compiler_error(self):
        """Test base MibAutoCompilerError"""
        error = MibAutoCompilerError("Test error", {'detail': 'test'})

        assert str(error) == "Test error (detail=test)"
        assert error.message == "Test error"
        assert error.details == {'detail': 'test'}

    def test_mib_download_error(self):
        """Test MibDownloadError"""
        sources = ['http://example1.com', 'http://example2.com']
        error = MibDownloadError('TEST-MIB', 'Download failed', sources)

        assert error.mib_name == 'TEST-MIB'
        assert error.source_urls == sources
        assert 'TEST-MIB' in str(error)

    def test_mib_compilation_error(self):
        """Test MibCompilationError"""
        deps = [{'name': 'DEP1', 'missing': True}]
        error = MibCompilationError('TEST-MIB', 'Compilation failed', deps)

        assert error.mib_name == 'TEST-MIB'
        assert error.compilation_error == 'Compilation failed'
        assert error.dependencies == deps


class TestIntegration:
    """Integration tests"""

    @pytest.fixture
    def integration_setup(self):
        """Setup for integration tests"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create vendor MIB directory
            vendor_dir = temp_path / "vendor_mibs"
            vendor_dir.mkdir()

            # Create output directory
            output_dir = temp_path / "output"
            output_dir.mkdir()

            # Create a simple test MIB
            test_mib = vendor_dir / "SIMPLE-TEST-MIB.mib"
            test_mib.write_text("""SIMPLE-TEST-MIB DEFINITIONS ::= BEGIN

IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Integer32
        FROM SNMPv2-SMI;

simpleTestMib MODULE-IDENTITY
    LAST-UPDATED "202401010000Z"
    ORGANIZATION "Test"
    CONTACT-INFO "test@test.com"
    DESCRIPTION "Simple test MIB"
    ::= { 1 3 6 1 4 1 99999 100 }

simpleTestObject OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Simple test object"
    ::= { simpleTestMib 1 }

END""")

            yield {
                'vendor_dir': vendor_dir,
                'output_dir': output_dir,
                'test_mib': test_mib
            }

    def test_end_to_end_workflow(self, integration_setup):
        """Test complete end-to-end workflow"""
        setup = integration_setup

        # Create configuration
        config = CompilerConfig(
            output_directory=str(setup['output_dir']),
            max_retries=1,
            download_timeout=5,
            preserve_downloads=True
        )

        # Initialize compiler
        compiler = MibAutoCompiler(
            vendor_mib_directory=str(setup['vendor_dir']),
            config=config
        )

        # Validate that setup worked
        assert compiler.vendor_mib_dir.exists()
        assert len(list(compiler.vendor_mib_dir.glob("*.mib"))) > 0

        # Test MIB detection
        detected_mibs = compiler.auto_detect_mibs()
        assert "SIMPLE-TEST-MIB" in detected_mibs

        # Test validation
        validation_results = compiler.validate_vendor_mibs()
        assert len(validation_results) > 0
        assert all(validation_results.values())  # All should be valid

        # Get statistics
        stats = compiler.get_compilation_stats()
        assert isinstance(stats, dict)
        assert 'mibs_processed' in stats


if __name__ == '__main__':
    pytest.main([__file__])