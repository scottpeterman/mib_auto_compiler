# mib_auto_downloader/exceptions.py
"""
Custom exceptions for MIB auto-downloader
"""


class MibAutoDownloaderError(Exception):
    """Base exception for MIB auto-downloader"""

    def __init__(self, message: str, details: dict = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self):
        if self.details:
            details_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            return f"{self.message} ({details_str})"
        return self.message


class MibDownloadError(MibAutoDownloaderError):
    """Raised when MIB download fails"""

    def __init__(self, mib_name: str, message: str = None, source_urls: list = None):
        self.mib_name = mib_name
        self.source_urls = source_urls or []

        if message is None:
            message = f"Failed to download MIB '{mib_name}'"
            if self.source_urls:
                message += f" from {len(self.source_urls)} source(s)"

        details = {
            'mib_name': mib_name,
            'sources_tried': len(self.source_urls)
        }

        super().__init__(message, details)


class MibCompilationError(MibAutoDownloaderError):
    """Raised when MIB compilation fails"""

    def __init__(self, mib_name: str, compilation_error: str = None, dependencies: list = None):
        self.mib_name = mib_name
        self.compilation_error = compilation_error
        self.dependencies = dependencies or []

        message = f"Failed to compile MIB '{mib_name}'"
        if compilation_error:
            message += f": {compilation_error}"

        details = {
            'mib_name': mib_name,
            'missing_dependencies': len([d for d in self.dependencies if d.get('missing', False)])
        }

        super().__init__(message, details)


class MibDependencyError(MibAutoDownloaderError):
    """Raised when MIB dependencies cannot be resolved"""

    def __init__(self, mib_name: str, missing_dependencies: list = None, circular_deps: list = None):
        self.mib_name = mib_name
        self.missing_dependencies = missing_dependencies or []
        self.circular_deps = circular_deps or []

        message = f"Dependency resolution failed for MIB '{mib_name}'"

        if self.missing_dependencies:
            message += f", missing {len(self.missing_dependencies)} dependencies"

        if self.circular_deps:
            message += f", {len(self.circular_deps)} circular dependencies detected"

        details = {
            'mib_name': mib_name,
            'missing_count': len(self.missing_dependencies),
            'circular_count': len(self.circular_deps),
            'missing_list': self.missing_dependencies,
            'circular_list': self.circular_deps
        }

        super().__init__(message, details)


class MibValidationError(MibAutoDownloaderError):
    """Raised when MIB validation fails"""

    def __init__(self, mib_name: str, validation_errors: list = None, file_path: str = None):
        self.mib_name = mib_name
        self.validation_errors = validation_errors or []
        self.file_path = file_path

        message = f"MIB validation failed for '{mib_name}'"
        if self.validation_errors:
            message += f" with {len(self.validation_errors)} error(s)"

        details = {
            'mib_name': mib_name,
            'error_count': len(self.validation_errors),
            'file_path': file_path,
            'errors': self.validation_errors
        }

        super().__init__(message, details)


class MibSourceError(MibAutoDownloaderError):
    """Raised when MIB source configuration is invalid"""

    def __init__(self, source_url: str, error_type: str = "invalid", message: str = None):
        self.source_url = source_url
        self.error_type = error_type

        if message is None:
            message = f"MIB source error: {error_type} source '{source_url}'"

        details = {
            'source_url': source_url,
            'error_type': error_type
        }

        super().__init__(message, details)


class MibCompilerSetupError(MibAutoDownloaderError):
    """Raised when MIB compiler setup fails"""

    def __init__(self, component: str = None, error_details: str = None):
        self.component = component
        self.error_details = error_details

        message = "MIB compiler setup failed"
        if component:
            message += f" during {component} initialization"
        if error_details:
            message += f": {error_details}"

        details = {
            'component': component,
            'error_details': error_details
        }

        super().__init__(message, details)


class MibParsingError(MibAutoDownloaderError):
    """Raised when MIB parsing fails"""

    def __init__(self, mib_name: str, line_number: int = None, syntax_error: str = None):
        self.mib_name = mib_name
        self.line_number = line_number
        self.syntax_error = syntax_error

        message = f"MIB parsing failed for '{mib_name}'"
        if line_number:
            message += f" at line {line_number}"
        if syntax_error:
            message += f": {syntax_error}"

        details = {
            'mib_name': mib_name,
            'line_number': line_number,
            'syntax_error': syntax_error
        }

        super().__init__(message, details)


class MibNotFoundError(MibAutoDownloaderError):
    """Raised when requested MIB cannot be found"""

    def __init__(self, mib_name: str, search_paths: list = None):
        self.mib_name = mib_name
        self.search_paths = search_paths or []

        message = f"MIB '{mib_name}' not found"
        if self.search_paths:
            message += f" in {len(self.search_paths)} search location(s)"

        details = {
            'mib_name': mib_name,
            'search_paths': self.search_paths,
            'paths_searched': len(self.search_paths)
        }

        super().__init__(message, details)


class MibOutputError(MibAutoDownloaderError):
    """Raised when MIB output operations fail"""

    def __init__(self, output_path: str, operation: str = "write", error_details: str = None):
        self.output_path = output_path
        self.operation = operation
        self.error_details = error_details

        message = f"MIB output {operation} failed for '{output_path}'"
        if error_details:
            message += f": {error_details}"

        details = {
            'output_path': output_path,
            'operation': operation,
            'error_details': error_details
        }

        super().__init__(message, details)


# Convenience functions for common exception scenarios

def raise_download_failed(mib_name: str, sources_tried: list = None, last_error: Exception = None):
    """Convenience function to raise MibDownloadError with context"""
    source_urls = sources_tried or []

    if last_error:
        message = f"Failed to download MIB '{mib_name}': {last_error}"
    else:
        message = f"Failed to download MIB '{mib_name}' from all sources"

    raise MibDownloadError(mib_name, message, source_urls) from last_error


def raise_compilation_failed(mib_name: str, pysmi_error: str = None, missing_deps: list = None):
    """Convenience function to raise MibCompilationError with context"""
    dependencies = []
    if missing_deps:
        dependencies = [{'name': dep, 'missing': True} for dep in missing_deps]

    raise MibCompilationError(mib_name, pysmi_error, dependencies)


def raise_dependency_error(mib_name: str, missing: list = None, circular: list = None):
    """Convenience function to raise MibDependencyError with context"""
    if not missing and not circular:
        missing = ["unknown"]

    raise MibDependencyError(mib_name, missing, circular)


def raise_validation_failed(mib_name: str, errors: list, file_path: str = None):
    """Convenience function to raise MibValidationError with context"""
    raise MibValidationError(mib_name, errors, file_path)


# Exception hierarchy for easy catching
class MibProcessingError(MibAutoDownloaderError):
    """Base class for MIB processing related errors"""
    pass


class MibNetworkError(MibAutoDownloaderError):
    """Base class for network-related MIB errors"""
    pass


# Reclassify existing exceptions into hierarchies
MibDownloadError.__bases__ = (MibNetworkError,)
MibSourceError.__bases__ = (MibNetworkError,)
MibCompilationError.__bases__ = (MibProcessingError,)
MibDependencyError.__bases__ = (MibProcessingError,)
MibValidationError.__bases__ = (MibProcessingError,)
MibParsingError.__bases__ = (MibProcessingError,)
MibCompilerSetupError.__bases__ = (MibProcessingError,)
MibNotFoundError.__bases__ = (MibProcessingError,)
MibOutputError.__bases__ = (MibProcessingError,)

# Export all exceptions
__all__ = [
    # Base exceptions
    'MibAutoDownloaderError',

    # Hierarchical base classes
    'MibProcessingError',
    'MibNetworkError',

    # Specific exceptions
    'MibDownloadError',
    'MibCompilationError',
    'MibDependencyError',
    'MibValidationError',
    'MibSourceError',
    'MibCompilerSetupError',
    'MibParsingError',
    'MibNotFoundError',
    'MibOutputError',

    # Convenience functions
    'raise_download_failed',
    'raise_compilation_failed',
    'raise_dependency_error',
    'raise_validation_failed'
]