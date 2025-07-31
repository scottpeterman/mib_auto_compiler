# mib_auto_downloader/utils.py
"""
Utility functions for MIB processing
"""

import re
import ast
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any
import logging

logger = logging.getLogger(__name__)


class MibValidator:
    """Validates MIB file syntax and content"""

    def validate_mib_file(self, mib_file: Path) -> bool:
        """Basic MIB file validation"""
        try:
            with open(mib_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Basic syntax checks
            if 'DEFINITIONS ::= BEGIN' not in content:
                logger.warning(f"{mib_file.name}: Missing DEFINITIONS ::= BEGIN")
                return False

            if not content.strip().endswith('END'):
                logger.warning(f"{mib_file.name}: Missing END statement")
                return False

            # Check for balanced braces
            open_braces = content.count('{')
            close_braces = content.count('}')
            if open_braces != close_braces:
                logger.warning(f"{mib_file.name}: Unbalanced braces ({open_braces} open, {close_braces} close)")
                return False

            return True

        except Exception as e:
            logger.error(f"Failed to validate {mib_file}: {e}")
            return False

    def check_mib_syntax(self, mib_file: Path) -> List[str]:
        """Perform detailed syntax checking and return list of issues"""
        issues = []

        try:
            with open(mib_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            # Check for common syntax issues
            for i, line in enumerate(lines, 1):
                line_stripped = line.strip()

                # Skip comments and empty lines
                if not line_stripped or line_stripped.startswith('--'):
                    continue

                # Check for missing semicolons
                if ('OBJECT-TYPE' in line or 'OBJECT IDENTIFIER' in line) and not line_stripped.endswith((';', ',')):
                    if i < len(lines) and not lines[i].strip().startswith(('::=', 'SYNTAX', 'ACCESS', 'STATUS')):
                        issues.append(f"Line {i}: Possible missing semicolon")

                # Check for invalid characters
                if any(ord(c) > 127 for c in line):
                    issues.append(f"Line {i}: Contains non-ASCII characters")

                # Check for tabs (should use spaces)
                if '\t' in line:
                    issues.append(f"Line {i}: Contains tab characters (use spaces)")

            return issues

        except Exception as e:
            return [f"Error reading file: {e}"]


def extract_mib_dependencies(mib_file: Path) -> Set[str]:
    """Extract MIB dependencies from IMPORTS section"""
    try:
        with open(mib_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Find IMPORTS section
        imports_match = re.search(r'IMPORTS\s*(.*?);', content, re.DOTALL)
        if not imports_match:
            return set()

        imports_section = imports_match.group(1)

        # Extract dependencies - look for "FROM mib-name" patterns
        dependencies = set()
        from_matches = re.findall(r'FROM\s+([A-Z][A-Z0-9-]*)', imports_section)
        dependencies.update(from_matches)

        return dependencies

    except Exception as e:
        logger.error(f"Failed to extract dependencies from {mib_file}: {e}")
        return set()


def extract_mib_info(mib_file: Path) -> Dict[str, Any]:
    """Extract comprehensive information from a MIB file"""
    try:
        with open(mib_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        info = {
            'file': str(mib_file),
            'name': None,
            'dependencies': set(),
            'imports': {},
            'object_types': [],
            'object_identifiers': [],
            'notifications': [],
            'size': mib_file.stat().st_size,
            'lines': len(content.split('\n'))
        }

        # Extract MIB name
        mib_name_match = re.search(r'^(\w+(?:-\w+)*)\s+DEFINITIONS\s*::=\s*BEGIN', content, re.MULTILINE)
        if mib_name_match:
            info['name'] = mib_name_match.group(1)

        # Extract dependencies
        info['dependencies'] = extract_mib_dependencies(mib_file)

        # Extract IMPORTS details
        imports_match = re.search(r'IMPORTS\s*(.*?);', content, re.DOTALL)
        if imports_match:
            imports_section = imports_match.group(1)
            info['imports'] = parse_imports_section(imports_section)

        # Extract OBJECT-TYPE definitions
        object_type_pattern = r'(\w+)\s+OBJECT-TYPE\s+(.*?)::=\s*\{([^}]+)\}'
        for match in re.finditer(object_type_pattern, content, re.DOTALL):
            obj_name = match.group(1)
            obj_def = match.group(2)
            obj_oid = match.group(3).strip()

            info['object_types'].append({
                'name': obj_name,
                'oid': obj_oid,
                'definition': obj_def.strip()
            })

        # Extract OBJECT IDENTIFIER definitions
        oid_pattern = r'(\w+)\s+OBJECT\s+IDENTIFIER\s*::=\s*\{([^}]+)\}'
        for match in re.finditer(oid_pattern, content):
            oid_name = match.group(1)
            oid_value = match.group(2).strip()

            info['object_identifiers'].append({
                'name': oid_name,
                'oid': oid_value
            })

        # Extract NOTIFICATION-TYPE definitions
        notif_pattern = r'(\w+)\s+NOTIFICATION-TYPE\s+(.*?)::=\s*\{([^}]+)\}'
        for match in re.finditer(notif_pattern, content, re.DOTALL):
            notif_name = match.group(1)
            notif_def = match.group(2)
            notif_oid = match.group(3).strip()

            info['notifications'].append({
                'name': notif_name,
                'oid': notif_oid,
                'definition': notif_def.strip()
            })

        return info

    except Exception as e:
        logger.error(f"Failed to extract MIB info from {mib_file}: {e}")
        return {'file': str(mib_file), 'error': str(e)}


def parse_imports_section(imports_section: str) -> Dict[str, List[str]]:
    """Parse IMPORTS section and return dict of MIB -> [imported items]"""
    imports = {}

    try:
        # Split by FROM to find import blocks
        lines = imports_section.split('\n')
        current_items = []

        for line in lines:
            line = line.strip()
            if not line or line.startswith('--'):
                continue

            if 'FROM' in line:
                # Extract MIB name after FROM
                from_match = re.search(r'FROM\s+([A-Z][A-Z0-9-]*)', line)
                if from_match:
                    mib_name = from_match.group(1)

                    # Extract items before FROM
                    items_part = line.split('FROM')[0].strip()
                    if current_items:
                        items_part = ', '.join(current_items) + ', ' + items_part

                    # Clean up the items
                    items = []
                    for item in re.split(r'[,\s]+', items_part):
                        item = item.strip(' ,')
                        if item and not item.startswith('--'):
                            items.append(item)

                    imports[mib_name] = items
                    current_items = []
            else:
                # Accumulate items for next FROM
                if line and not line.startswith('--'):
                    current_items.append(line.strip(' ,'))

        return imports

    except Exception as e:
        logger.error(f"Failed to parse imports section: {e}")
        return {}


def extract_oids_from_compiled_mib(compiled_mib_file: Path) -> List[Dict[str, Any]]:
    """Extract OID information from compiled Python MIB module"""
    oids = []

    try:
        with open(compiled_mib_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Parse the Python AST to extract MIB objects
        tree = ast.parse(content)

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                # Look for MIB object assignments
                if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    var_name = node.targets[0].id

                    # Check if it's a MIB object (heuristic)
                    if isinstance(node.value, ast.Call):
                        func_name = None
                        if isinstance(node.value.func, ast.Name):
                            func_name = node.value.func.id
                        elif isinstance(node.value.func, ast.Attribute):
                            func_name = node.value.func.attr

                        if func_name in ['MibIdentifier', 'MibScalar', 'MibTable', 'MibTableRow', 'MibTableColumn']:
                            oid_info = {
                                'name': var_name,
                                'type': func_name,
                                'line': node.lineno
                            }

                            # Try to extract OID value
                            if node.value.args:
                                first_arg = node.value.args[0]
                                if isinstance(first_arg, (ast.Tuple, ast.List)):
                                    # OID is likely a tuple/list of numbers
                                    oid_parts = []
                                    for elt in first_arg.elts:
                                        if isinstance(elt, ast.Constant):
                                            oid_parts.append(str(elt.value))
                                    if oid_parts:
                                        oid_info['oid'] = '.'.join(oid_parts)

                            oids.append(oid_info)

        return oids

    except Exception as e:
        logger.error(f"Failed to extract OIDs from compiled MIB {compiled_mib_file}: {e}")
        return []


def sort_mibs_by_dependencies(mib_files: List[Path]) -> List[Path]:
    """Sort MIB files by dependency order (dependencies first)"""
    # Build dependency graph
    mib_info = {}
    for mib_file in mib_files:
        info = extract_mib_info(mib_file)
        if info.get('name'):
            mib_info[info['name']] = {
                'file': mib_file,
                'dependencies': info['dependencies']
            }

    # Available MIBs (those we have files for)
    available_mibs = set(mib_info.keys())

    # Topological sort
    sorted_files = []
    processed = set()

    def visit(mib_name):
        if mib_name in processed:
            return

        if mib_name in mib_info:
            # Process dependencies first
            for dep in mib_info[mib_name]['dependencies']:
                if dep in available_mibs:
                    visit(dep)

            # Add this MIB
            processed.add(mib_name)
            sorted_files.append(mib_info[mib_name]['file'])

    # Visit all MIBs
    for mib_name in mib_info:
        visit(mib_name)

    # Add any files that couldn't be processed (no name extracted)
    for mib_file in mib_files:
        if mib_file not in sorted_files:
            sorted_files.append(mib_file)

    return sorted_files


def generate_dependency_graph(mib_files: List[Path]) -> Dict[str, Any]:
    """Generate a dependency graph for visualization"""
    graph = {
        'nodes': [],
        'edges': [],
        'stats': {}
    }

    mib_info = {}
    all_dependencies = set()

    # Extract info from all MIBs
    for mib_file in mib_files:
        info = extract_mib_info(mib_file)
        if info.get('name'):
            mib_name = info['name']
            mib_info[mib_name] = info
            all_dependencies.update(info['dependencies'])

            # Add node
            graph['nodes'].append({
                'id': mib_name,
                'label': mib_name,
                'file': str(mib_file),
                'size': info['size'],
                'object_count': len(info['object_types']) + len(info['object_identifiers'])
            })

    # Add edges for dependencies
    for mib_name, info in mib_info.items():
        for dep in info['dependencies']:
            graph['edges'].append({
                'from': dep,
                'to': mib_name,
                'type': 'dependency'
            })

    # Calculate stats
    available_mibs = set(mib_info.keys())
    missing_deps = all_dependencies - available_mibs

    graph['stats'] = {
        'total_mibs': len(mib_info),
        'total_dependencies': len(all_dependencies),
        'missing_dependencies': len(missing_deps),
        'missing_list': list(missing_deps),
        'dependency_ratio': len(all_dependencies) / len(mib_info) if mib_info else 0
    }

    return graph


def validate_compiled_mib(compiled_file: Path) -> Dict[str, Any]:
    """Validate a compiled Python MIB module"""
    validation = {
        'valid': False,
        'errors': [],
        'warnings': [],
        'stats': {}
    }

    try:
        # Check if file exists and is readable
        if not compiled_file.exists():
            validation['errors'].append("File does not exist")
            return validation

        with open(compiled_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Try to parse as Python
        try:
            tree = ast.parse(content)
            validation['stats']['syntax_valid'] = True
        except SyntaxError as e:
            validation['errors'].append(f"Python syntax error: {e}")
            return validation

        # Check for expected MIB components
        mib_objects = 0
        imports = 0

        for node in ast.walk(tree):
            if isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom):
                imports += 1
            elif isinstance(node, ast.Assign):
                if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    var_name = node.targets[0].id
                    if isinstance(node.value, ast.Call):
                        func_name = None
                        if isinstance(node.value.func, ast.Name):
                            func_name = node.value.func.id
                        elif isinstance(node.value.func, ast.Attribute):
                            func_name = node.value.func.attr

                        if func_name and 'Mib' in func_name:
                            mib_objects += 1

        validation['stats'].update({
            'file_size': compiled_file.stat().st_size,
            'line_count': len(content.split('\n')),
            'mib_objects': mib_objects,
            'imports': imports
        })

        # Validation checks
        if mib_objects == 0:
            validation['warnings'].append("No MIB objects found")

        if imports == 0:
            validation['warnings'].append("No imports found")

        # Check for pysnmp imports
        if 'pysnmp' not in content:
            validation['warnings'].append("No pysnmp imports detected")

        validation['valid'] = len(validation['errors']) == 0

        return validation

    except Exception as e:
        validation['errors'].append(f"Validation error: {e}")
        return validation


def create_mib_summary_report(mib_directory: Path, compiled_directory: Path = None) -> str:
    """Create a comprehensive summary report of MIB files and compilation"""

    # Find MIB files
    mib_files = list(mib_directory.glob("*.mib"))

    report = []
    report.append("MIB ANALYSIS SUMMARY REPORT")
    report.append("=" * 50)
    report.append(f"Source Directory: {mib_directory}")
    report.append(f"Total MIB Files: {len(mib_files)}")
    report.append("")

    # Analyze each MIB
    total_size = 0
    total_objects = 0
    all_dependencies = set()
    mib_info_list = []

    for mib_file in mib_files:
        info = extract_mib_info(mib_file)
        mib_info_list.append(info)

        total_size += info.get('size', 0)
        total_objects += len(info.get('object_types', []))
        all_dependencies.update(info.get('dependencies', set()))

    # Overall statistics
    report.append("OVERALL STATISTICS")
    report.append("-" * 20)
    report.append(f"Total Size: {total_size:,} bytes")
    report.append(f"Total Object Types: {total_objects}")
    report.append(f"Unique Dependencies: {len(all_dependencies)}")
    report.append("")

    # Individual MIB details
    report.append("INDIVIDUAL MIB ANALYSIS")
    report.append("-" * 25)

    for info in sorted(mib_info_list, key=lambda x: x.get('name', '')):
        name = info.get('name', 'Unknown')
        size = info.get('size', 0)
        obj_count = len(info.get('object_types', []))
        dep_count = len(info.get('dependencies', []))

        report.append(f"{name}:")
        report.append(f"  Size: {size:,} bytes")
        report.append(f"  Objects: {obj_count}")
        report.append(f"  Dependencies: {dep_count}")

        if info.get('dependencies'):
            deps = ', '.join(sorted(info['dependencies']))
            report.append(f"  Imports from: {deps}")
        report.append("")

    # Dependency analysis
    available_mibs = {info['name'] for info in mib_info_list if info.get('name')}
    missing_deps = all_dependencies - available_mibs

    report.append("DEPENDENCY ANALYSIS")
    report.append("-" * 18)
    report.append(f"Available MIBs: {len(available_mibs)}")
    report.append(f"External Dependencies: {len(missing_deps)}")

    if missing_deps:
        report.append("Missing Dependencies:")
        for dep in sorted(missing_deps):
            report.append(f"  - {dep}")
    report.append("")

    # Compilation analysis (if compiled directory provided)
    if compiled_directory and compiled_directory.exists():
        compiled_files = list(compiled_directory.glob("*.py"))

        report.append("COMPILATION ANALYSIS")
        report.append("-" * 19)
        report.append(f"Compiled Files: {len(compiled_files)}")

        success_rate = (len(compiled_files) / len(mib_files)) * 100 if mib_files else 0
        report.append(f"Success Rate: {success_rate:.1f}%")

        total_compiled_size = sum(f.stat().st_size for f in compiled_files)
        report.append(f"Total Compiled Size: {total_compiled_size:,} bytes")
        report.append("")

        # Validation of compiled files
        valid_count = 0
        for compiled_file in compiled_files:
            validation = validate_compiled_mib(compiled_file)
            if validation['valid']:
                valid_count += 1

        report.append(f"Valid Compiled Files: {valid_count}/{len(compiled_files)}")
        report.append("")

    return '\n'.join(report)


def extract_discovery_oids(compiled_mib_files: List[Path],
                           filter_patterns: List[str] = None) -> Dict[str, List[str]]:
    """Extract OIDs useful for network discovery from compiled MIBs"""

    if filter_patterns is None:
        # Default patterns for discovery-relevant OIDs
        filter_patterns = [
            r'.*[Ss]ys.*',  # System information
            r'.*[Mm]odel.*',  # Model information
            r'.*[Ss]erial.*',  # Serial numbers
            r'.*[Vv]ersion.*',  # Version information
            r'.*[Ss]tatus.*',  # Status information
            r'.*[Ii]nterface.*',  # Interface information
            r'.*[Ee]ntity.*',  # Entity information
        ]

    discovery_oids = {}

    for mib_file in compiled_mib_files:
        mib_name = mib_file.stem
        oids = extract_oids_from_compiled_mib(mib_file)

        # Filter OIDs based on patterns
        filtered_oids = []
        for oid_info in oids:
            oid_name = oid_info.get('name', '')

            for pattern in filter_patterns:
                if re.match(pattern, oid_name, re.IGNORECASE):
                    if oid_info.get('oid'):
                        filtered_oids.append(oid_info['oid'])
                    break

        if filtered_oids:
            discovery_oids[mib_name] = filtered_oids

    return discovery_oids