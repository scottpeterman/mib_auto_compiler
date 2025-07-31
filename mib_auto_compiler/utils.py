"""
Enhanced utility functions for MIB processing
"""

import re
import ast
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any, Union
import logging
import hashlib
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class MibValidator:
    """Enhanced MIB file validator with detailed reporting"""

    def __init__(self):
        self.validation_cache = {}

    def validate_mib_file(self, mib_file: Path) -> bool:
        """Basic MIB file validation with caching"""
        # Check cache first
        file_hash = self._get_file_hash(mib_file)
        if file_hash in self.validation_cache:
            return self.validation_cache[file_hash]

        try:
            with open(mib_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            is_valid = self._validate_content(content, mib_file.name)
            self.validation_cache[file_hash] = is_valid

            return is_valid

        except Exception as e:
            logger.error(f"Failed to validate {mib_file}: {e}")
            return False

    def _validate_content(self, content: str, filename: str) -> bool:
        """Validate MIB content"""
        # Basic syntax checks
        if 'DEFINITIONS ::= BEGIN' not in content:
            logger.warning(f"{filename}: Missing DEFINITIONS ::= BEGIN")
            return False

        if not content.strip().endswith('END'):
            logger.warning(f"{filename}: Missing END statement")
            return False

        # Check for balanced braces
        open_braces = content.count('{')
        close_braces = content.count('}')
        if open_braces != close_braces:
            logger.warning(f"{filename}: Unbalanced braces ({open_braces} open, {close_braces} close)")
            return False

        # Check for valid MIB name
        mib_name_match = re.search(r'^(\w+(?:-\w+)*)\s+DEFINITIONS\s*::=\s*BEGIN', content, re.MULTILINE)
        if not mib_name_match:
            logger.warning(f"{filename}: Cannot extract valid MIB name")
            return False

        return True

    def check_mib_syntax(self, mib_file: Path) -> Dict[str, Any]:
        """Perform detailed syntax checking and return detailed report"""
        report = {
            'file': str(mib_file),
            'valid': False,
            'errors': [],
            'warnings': [],
            'info': {},
            'statistics': {}
        }

        try:
            with open(mib_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

            # Basic statistics
            report['statistics'] = {
                'file_size': mib_file.stat().st_size,
                'line_count': len(lines),
                'non_empty_lines': len([l for l in lines if l.strip()]),
                'comment_lines': len([l for l in lines if l.strip().startswith('--')]),
            }

            # Extract MIB information
            mib_info = self._extract_mib_metadata(content)
            report['info'] = mib_info

            # Check for common syntax issues
            syntax_issues = self._check_syntax_issues(lines)
            report['errors'].extend(syntax_issues['errors'])
            report['warnings'].extend(syntax_issues['warnings'])

            # Overall validation
            report['valid'] = len(report['errors']) == 0

            return report

        except Exception as e:
            report['errors'].append(f"Error reading file: {e}")
            return report

    def _extract_mib_metadata(self, content: str) -> Dict[str, Any]:
        """Extract metadata from MIB content"""
        metadata = {}

        # Extract MIB name
        mib_name_match = re.search(r'^(\w+(?:-\w+)*)\s+DEFINITIONS\s*::=\s*BEGIN', content, re.MULTILINE)
        if mib_name_match:
            metadata['name'] = mib_name_match.group(1)

        # Extract revision information
        revisions = []
        revision_pattern = r'REVISION\s+"([^"]+)"\s+DESCRIPTION\s+"([^"]*)"'
        for match in re.finditer(revision_pattern, content, re.DOTALL):
            revisions.append({
                'date': match.group(1),
                'description': match.group(2).strip()
            })
        metadata['revisions'] = revisions

        # Extract organization and contact info
        org_match = re.search(r'ORGANIZATION\s+"([^"]*)"', content)
        if org_match:
            metadata['organization'] = org_match.group(1)

        contact_match = re.search(r'CONTACT-INFO\s+"([^"]*)"', content, re.DOTALL)
        if contact_match:
            metadata['contact_info'] = contact_match.group(1).strip()

        # Count different object types
        metadata['object_counts'] = {
            'object_types': len(re.findall(r'\w+\s+OBJECT-TYPE', content)),
            'object_identifiers': len(re.findall(r'\w+\s+OBJECT\s+IDENTIFIER', content)),
            'notifications': len(re.findall(r'\w+\s+NOTIFICATION-TYPE', content)),
            'textual_conventions': len(re.findall(r'\w+\s*::=\s*TEXTUAL-CONVENTION', content)),
        }

        return metadata

    def _check_syntax_issues(self, lines: List[str]) -> Dict[str, List[str]]:
        """Check for common syntax issues"""
        issues = {'errors': [], 'warnings': []}

        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()

            # Skip comments and empty lines
            if not line_stripped or line_stripped.startswith('--'):
                continue

            # Check for invalid characters
            if any(ord(c) > 127 for c in line):
                issues['warnings'].append(f"Line {i}: Contains non-ASCII characters")

            # Check for tabs (should use spaces)
            if '\t' in line:
                issues['warnings'].append(f"Line {i}: Contains tab characters (use spaces)")

            # Check for long lines
            if len(line) > 120:
                issues['warnings'].append(f"Line {i}: Line too long ({len(line)} characters)")

            # Check for missing semicolons in specific contexts
            if ('OBJECT-TYPE' in line or 'OBJECT IDENTIFIER' in line) and not line_stripped.endswith((';', ',')):
                if i < len(lines) and not lines[i].strip().startswith(('::=', 'SYNTAX', 'ACCESS', 'STATUS')):
                    issues['warnings'].append(f"Line {i}: Possible missing semicolon")

        return issues

    def _get_file_hash(self, file_path: Path) -> str:
        """Generate hash for file caching"""
        stat = file_path.stat()
        content = f"{file_path}:{stat.st_size}:{stat.st_mtime}"
        return hashlib.md5(content.encode()).hexdigest()


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
            'textual_conventions': [],
            'size': mib_file.stat().st_size,
            'lines': len(content.split('\n')),
            'last_modified': datetime.fromtimestamp(mib_file.stat().st_mtime).isoformat(),
            'metadata': {}
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

        # Extract various object definitions
        info['object_types'] = extract_object_types(content)
        info['object_identifiers'] = extract_object_identifiers(content)
        info['notifications'] = extract_notifications(content)
        info['textual_conventions'] = extract_textual_conventions(content)

        # Extract metadata
        info['metadata'] = extract_mib_metadata(content)

        return info

    except Exception as e:
        logger.error(f"Failed to extract MIB info from {mib_file}: {e}")
        return {'file': str(mib_file), 'error': str(e)}


def extract_object_types(content: str) -> List[Dict[str, Any]]:
    """Extract OBJECT-TYPE definitions"""
    object_types = []

    # More comprehensive pattern for OBJECT-TYPE
    pattern = r'(\w+)\s+OBJECT-TYPE\s+(.*?)::=\s*\{([^}]+)\}'

    for match in re.finditer(pattern, content, re.DOTALL):
        obj_name = match.group(1)
        obj_def = match.group(2).strip()
        obj_oid = match.group(3).strip()

        # Parse the definition for more details
        obj_info = {
            'name': obj_name,
            'oid': obj_oid,
            'definition': obj_def,
            'syntax': None,
            'access': None,
            'status': None,
            'description': None
        }

        # Extract specific fields
        syntax_match = re.search(r'SYNTAX\s+([^\n\r]+)', obj_def)
        if syntax_match:
            obj_info['syntax'] = syntax_match.group(1).strip()

        access_match = re.search(r'(?:ACCESS|MAX-ACCESS)\s+([^\n\r]+)', obj_def)
        if access_match:
            obj_info['access'] = access_match.group(1).strip()

        status_match = re.search(r'STATUS\s+([^\n\r]+)', obj_def)
        if status_match:
            obj_info['status'] = status_match.group(1).strip()

        desc_match = re.search(r'DESCRIPTION\s+"([^"]*)"', obj_def, re.DOTALL)
        if desc_match:
            obj_info['description'] = desc_match.group(1).strip()

        object_types.append(obj_info)

    return object_types


def extract_object_identifiers(content: str) -> List[Dict[str, Any]]:
    """Extract OBJECT IDENTIFIER definitions"""
    object_identifiers = []

    pattern = r'(\w+)\s+OBJECT\s+IDENTIFIER\s*::=\s*\{([^}]+)\}'

    for match in re.finditer(pattern, content):
        oid_name = match.group(1)
        oid_value = match.group(2).strip()

        object_identifiers.append({
            'name': oid_name,
            'oid': oid_value,
            'type': 'OBJECT IDENTIFIER'
        })

    return object_identifiers


def extract_notifications(content: str) -> List[Dict[str, Any]]:
    """Extract NOTIFICATION-TYPE definitions"""
    notifications = []

    pattern = r'(\w+)\s+NOTIFICATION-TYPE\s+(.*?)::=\s*\{([^}]+)\}'

    for match in re.finditer(pattern, content, re.DOTALL):
        notif_name = match.group(1)
        notif_def = match.group(2).strip()
        notif_oid = match.group(3).strip()

        notif_info = {
            'name': notif_name,
            'oid': notif_oid,
            'definition': notif_def,
            'objects': [],
            'status': None,
            'description': None
        }

        # Extract OBJECTS clause
        objects_match = re.search(r'OBJECTS\s*\{([^}]+)\}', notif_def)
        if objects_match:
            objects_str = objects_match.group(1)
            objects = [obj.strip() for obj in objects_str.split(',') if obj.strip()]
            notif_info['objects'] = objects

        # Extract status and description
        status_match = re.search(r'STATUS\s+([^\n\r]+)', notif_def)
        if status_match:
            notif_info['status'] = status_match.group(1).strip()

        desc_match = re.search(r'DESCRIPTION\s+"([^"]*)"', notif_def, re.DOTALL)
        if desc_match:
            notif_info['description'] = desc_match.group(1).strip()

        notifications.append(notif_info)

    return notifications


def extract_textual_conventions(content: str) -> List[Dict[str, Any]]:
    """Extract TEXTUAL-CONVENTION definitions"""
    textual_conventions = []

    pattern = r'(\w+)\s*::=\s*TEXTUAL-CONVENTION\s+(.*?)(?=\n\w|\nEND|\Z)'

    for match in re.finditer(pattern, content, re.DOTALL):
        tc_name = match.group(1)
        tc_def = match.group(2).strip()

        tc_info = {
            'name': tc_name,
            'definition': tc_def,
            'display_hint': None,
            'status': None,
            'description': None,
            'syntax': None
        }

        # Extract specific fields
        hint_match = re.search(r'DISPLAY-HINT\s+"([^"]*)"', tc_def)
        if hint_match:
            tc_info['display_hint'] = hint_match.group(1)

        status_match = re.search(r'STATUS\s+([^\n\r]+)', tc_def)
        if status_match:
            tc_info['status'] = status_match.group(1).strip()

        desc_match = re.search(r'DESCRIPTION\s+"([^"]*)"', tc_def, re.DOTALL)
        if desc_match:
            tc_info['description'] = desc_match.group(1).strip()

        syntax_match = re.search(r'SYNTAX\s+([^\n\r]+)', tc_def)
        if syntax_match:
            tc_info['syntax'] = syntax_match.group(1).strip()

        textual_conventions.append(tc_info)

    return textual_conventions


def extract_mib_metadata(content: str) -> Dict[str, Any]:
    """Extract metadata from MIB content"""
    metadata = {}

    # Extract organization
    org_match = re.search(r'ORGANIZATION\s+"([^"]*)"', content)
    if org_match:
        metadata['organization'] = org_match.group(1)

    # Extract contact info
    contact_match = re.search(r'CONTACT-INFO\s+"([^"]*)"', content, re.DOTALL)
    if contact_match:
        metadata['contact_info'] = contact_match.group(1).strip()

    # Extract description
    desc_match = re.search(r'DESCRIPTION\s+"([^"]*)"', content, re.DOTALL)
    if desc_match:
        metadata['description'] = desc_match.group(1).strip()

    # Extract revisions
    revisions = []
    revision_pattern = r'REVISION\s+"([^"]+)"\s+DESCRIPTION\s+"([^"]*)"'
    for match in re.finditer(revision_pattern, content, re.DOTALL):
        revisions.append({
            'date': match.group(1),
            'description': match.group(2).strip()
        })
    metadata['revisions'] = revisions

    return metadata


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


def analyze_mib_directory(mib_directory: Path,
                         include_dependencies: bool = False,
                         include_objects: bool = False) -> Dict[str, Any]:
    """Comprehensive analysis of all MIBs in a directory"""

    analysis = {
        'directory': str(mib_directory),
        'timestamp': datetime.now().isoformat(),
        'summary': {},
        'mibs': [],
        'dependencies': {},
        'statistics': {}
    }

    if not mib_directory.exists():
        analysis['error'] = f"Directory not found: {mib_directory}"
        return analysis

    # Find all MIB files
    mib_files = (
        list(mib_directory.glob("*.mib")) +
        list(mib_directory.glob("*.txt")) +
        list(mib_directory.glob("*.my"))
    )

    logger.info(f"Analyzing {len(mib_files)} MIB files in {mib_directory}")

    # Analyze each MIB
    total_size = 0
    total_objects = 0
    all_dependencies = set()
    mib_names = set()

    for mib_file in mib_files:
        try:
            mib_info = extract_mib_info(mib_file)

            # Add to analysis
            analysis['mibs'].append(mib_info)

            # Update statistics
            total_size += mib_info.get('size', 0)
            total_objects += len(mib_info.get('object_types', []))
            all_dependencies.update(mib_info.get('dependencies', set()))

            if mib_info.get('name'):
                mib_names.add(mib_info['name'])

        except Exception as e:
            logger.error(f"Failed to analyze {mib_file}: {e}")
            analysis['mibs'].append({
                'file': str(mib_file),
                'error': str(e)
            })

    # Generate summary
    analysis['summary'] = {
        'total_files': len(mib_files),
        'total_size': total_size,
        'total_objects': total_objects,
        'unique_dependencies': len(all_dependencies),
        'unique_mib_names': len(mib_names)
    }

    # Dependency analysis
    if include_dependencies:
        available_mibs = mib_names
        missing_deps = all_dependencies - available_mibs

        analysis['dependencies'] = {
            'total_dependencies': len(all_dependencies),
            'available_internal': len(all_dependencies & available_mibs),
            'missing_external': len(missing_deps),
            'missing_list': list(missing_deps),
            'dependency_graph': generate_dependency_graph_data([mib for mib in analysis['mibs'] if 'error' not in mib])
        }

    # Additional statistics
    analysis['statistics'] = {
        'average_file_size': total_size / len(mib_files) if mib_files else 0,
        'average_objects_per_mib': total_objects / len([m for m in analysis['mibs'] if 'error' not in m]) if analysis['mibs'] else 0,
        'file_extensions': {
            '.mib': len([f for f in mib_files if f.suffix == '.mib']),
            '.txt': len([f for f in mib_files if f.suffix == '.txt']),
            '.my': len([f for f in mib_files if f.suffix == '.my'])
        }
    }

    return analysis


def generate_dependency_graph_data(mib_info_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate dependency graph data for visualization"""

    graph = {
        'nodes': [],
        'edges': [],
        'clusters': {},
        'metrics': {}
    }

    # Create nodes
    mib_map = {}
    for mib_info in mib_info_list:
        if mib_info.get('name'):
            mib_name = mib_info['name']
            mib_map[mib_name] = mib_info

            graph['nodes'].append({
                'id': mib_name,
                'label': mib_name,
                'size': mib_info.get('size', 0),
                'objects': len(mib_info.get('object_types', [])),
                'file': mib_info.get('file', ''),
                'type': 'internal'
            })

    # Create edges and external nodes
    external_deps = set()
    for mib_info in mib_info_list:
        if mib_info.get('name') and mib_info.get('dependencies'):
            source = mib_info['name']

            for dep in mib_info['dependencies']:
                if dep in mib_map:
                    # Internal dependency
                    graph['edges'].append({
                        'from': dep,
                        'to': source,
                        'type': 'internal'
                    })
                else:
                    # External dependency
                    external_deps.add(dep)
                    graph['edges'].append({
                        'from': dep,
                        'to': source,
                        'type': 'external'
                    })

    # Add external dependency nodes
    for dep in external_deps:
        graph['nodes'].append({
            'id': dep,
            'label': dep,
            'type': 'external',
            'size': 0,
            'objects': 0
        })

    # Calculate metrics
    graph['metrics'] = {
        'total_nodes': len(graph['nodes']),
        'internal_nodes': len([n for n in graph['nodes'] if n['type'] == 'internal']),
        'external_nodes': len([n for n in graph['nodes'] if n['type'] == 'external']),
        'total_edges': len(graph['edges']),
        'internal_edges': len([e for e in graph['edges'] if e['type'] == 'internal']),
        'external_edges': len([e for e in graph['edges'] if e['type'] == 'external'])
    }

    return graph


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

    # Topological sort with cycle detection
    sorted_files = []
    processed = set()
    processing = set()

    def visit(mib_name, path=None):
        if path is None:
            path = []

        if mib_name in processing:
            # Circular dependency detected
            cycle = path[path.index(mib_name):] + [mib_name]
            logger.warning(f"Circular dependency detected: {' -> '.join(cycle)}")
            return

        if mib_name in processed:
            return

        if mib_name in mib_info:
            processing.add(mib_name)
            path.append(mib_name)

            # Process dependencies first
            for dep in mib_info[mib_name]['dependencies']:
                if dep in available_mibs:
                    visit(dep, path.copy())

            # Add this MIB
            processing.remove(mib_name)
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


def extract_discovery_oids_from_directory(compiled_directory: Path,
                                        filter_patterns: Optional[List[str]] = None) -> Dict[str, List[str]]:
    """Extract discovery OIDs from all compiled MIB files in a directory"""

    if not compiled_directory.exists():
        logger.error(f"Compiled directory not found: {compiled_directory}")
        return {}

    compiled_files = list(compiled_directory.glob("*.py"))
    if not compiled_files:
        logger.warning(f"No compiled Python files found in {compiled_directory}")
        return {}

    return extract_discovery_oids(compiled_files, filter_patterns)


def extract_discovery_oids(compiled_mib_files: List[Path],
                          filter_patterns: Optional[List[str]] = None) -> Dict[str, List[str]]:
    """Extract OIDs useful for network discovery from compiled MIBs"""

    if filter_patterns is None:
        # Default patterns for discovery-relevant OIDs
        filter_patterns = [
            r'.*[Ss]ys.*',           # System information
            r'.*[Mm]odel.*',         # Model information
            r'.*[Ss]erial.*',        # Serial numbers
            r'.*[Vv]ersion.*',       # Version information
            r'.*[Ss]tatus.*',        # Status information
            r'.*[Ii]nterface.*',     # Interface information
            r'.*[Ee]ntity.*',        # Entity information
            r'.*[Dd]escr.*',         # Description fields
            r'.*[Nn]ame.*',          # Name fields
            r'.*[Tt]ype.*',          # Type information
            r'.*[Ll]ocation.*',      # Location information
            r'.*[Cc]ontact.*',       # Contact information
            r'.*[Uu]ptime.*',        # Uptime information
        ]

    discovery_oids = {}

    for mib_file in compiled_mib_files:
        try:
            mib_name = mib_file.stem
            oids = extract_oids_from_compiled_mib(mib_file)

            # Filter OIDs based on patterns
            filtered_oids = []
            for oid_info in oids:
                oid_name = oid_info.get('name', '')

                for pattern in filter_patterns:
                    if re.match(pattern, oid_name, re.IGNORECASE):
                        if oid_info.get('oid'):
                            filtered_oids.append({
                                'name': oid_name,
                                'oid': oid_info['oid'],
                                'type': oid_info.get('type', 'unknown')
                            })
                        break

            if filtered_oids:
                discovery_oids[mib_name] = filtered_oids

        except Exception as e:
            logger.error(f"Failed to extract OIDs from {mib_file}: {e}")

    return discovery_oids


def extract_oids_from_compiled_mib(compiled_mib_file: Path) -> List[Dict[str, Any]]:
    """Extract OID information from compiled Python MIB module"""
    oids = []

    try:
        with open(compiled_mib_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Parse the Python AST to extract MIB objects
        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            logger.error(f"Syntax error in compiled MIB {compiled_mib_file}: {e}")
            return []

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

                        if func_name and any(mib_type in func_name for mib_type in
                                           ['MibIdentifier', 'MibScalar', 'MibTable', 'MibTableRow', 'MibTableColumn']):
                            oid_info = {
                                'name': var_name,
                                'type': func_name,
                                'line': node.lineno,
                                'oid': None
                            }

                            # Try to extract OID value
                            if node.value.args:
                                first_arg = node.value.args[0]
                                oid_value = extract_oid_from_ast_node(first_arg)
                                if oid_value:
                                    oid_info['oid'] = oid_value

                            oids.append(oid_info)

        return oids

    except Exception as e:
        logger.error(f"Failed to extract OIDs from compiled MIB {compiled_mib_file}: {e}")
        return []


def extract_oid_from_ast_node(node: ast.AST) -> Optional[str]:
    """Extract OID string from AST node"""
    try:
        if isinstance(node, (ast.Tuple, ast.List)):
            # OID is likely a tuple/list of numbers
            oid_parts = []
            for elt in node.elts:
                if isinstance(elt, ast.Constant):
                    oid_parts.append(str(elt.value))
                elif isinstance(elt, ast.Num):  # Python < 3.8 compatibility
                    oid_parts.append(str(elt.n))
            if oid_parts:
                return '.'.join(oid_parts)

        elif isinstance(node, ast.Constant):
            # Direct string or number
            return str(node.value)

        elif isinstance(node, ast.Str):  # Python < 3.8 compatibility
            return node.s

    except Exception:
        pass

    return None


def validate_compiled_mib(compiled_file: Path) -> Dict[str, Any]:
    """Validate a compiled Python MIB module"""
    validation = {
        'file': str(compiled_file),
        'valid': False,
        'errors': [],
        'warnings': [],
        'statistics': {},
        'metadata': {}
    }

    try:
        # Check if file exists and is readable
        if not compiled_file.exists():
            validation['errors'].append("File does not exist")
            return validation

        with open(compiled_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Basic statistics
        validation['statistics'] = {
            'file_size': compiled_file.stat().st_size,
            'line_count': len(content.split('\n')),
            'last_modified': datetime.fromtimestamp(compiled_file.stat().st_mtime).isoformat()
        }

        # Try to parse as Python
        try:
            tree = ast.parse(content)
            validation['statistics']['syntax_valid'] = True
        except SyntaxError as e:
            validation['errors'].append(f"Python syntax error: {e}")
            return validation

        # Analyze the AST
        analysis = analyze_compiled_mib_ast(tree, content)
        validation['statistics'].update(analysis['statistics'])
        validation['metadata'] = analysis['metadata']
        validation['warnings'].extend(analysis['warnings'])

        # Validation checks
        if analysis['statistics']['mib_objects'] == 0:
            validation['warnings'].append("No MIB objects found")

        if analysis['statistics']['imports'] == 0:
            validation['warnings'].append("No imports found")

        # Check for pysnmp imports
        if not analysis['metadata']['has_pysnmp_imports']:
            validation['warnings'].append("No pysnmp imports detected")

        # Check if it looks like a valid compiled MIB
        if not analysis['metadata']['looks_like_mib']:
            validation['warnings'].append("File doesn't appear to be a compiled MIB")

        validation['valid'] = len(validation['errors']) == 0

        return validation

    except Exception as e:
        validation['errors'].append(f"Validation error: {e}")
        return validation


def analyze_compiled_mib_ast(tree: ast.AST, content: str) -> Dict[str, Any]:
    """Analyze compiled MIB AST for detailed information"""

    analysis = {
        'statistics': {
            'mib_objects': 0,
            'imports': 0,
            'functions': 0,
            'classes': 0,
            'assignments': 0
        },
        'metadata': {
            'has_pysnmp_imports': False,
            'looks_like_mib': False,
            'mib_name': None,
            'imports_list': [],
            'mib_object_types': []
        },
        'warnings': []
    }

    # Walk through AST nodes
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            analysis['statistics']['imports'] += 1

            # Check for pysnmp imports
            if isinstance(node, ast.ImportFrom):
                if node.module and 'pysnmp' in node.module:
                    analysis['metadata']['has_pysnmp_imports'] = True
                    analysis['metadata']['imports_list'].append(node.module)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if 'pysnmp' in alias.name:
                        analysis['metadata']['has_pysnmp_imports'] = True
                        analysis['metadata']['imports_list'].append(alias.name)

        elif isinstance(node, ast.FunctionDef):
            analysis['statistics']['functions'] += 1

        elif isinstance(node, ast.ClassDef):
            analysis['statistics']['classes'] += 1

        elif isinstance(node, ast.Assign):
            analysis['statistics']['assignments'] += 1

            # Check for MIB objects
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                var_name = node.targets[0].id

                if isinstance(node.value, ast.Call):
                    func_name = None
                    if isinstance(node.value.func, ast.Name):
                        func_name = node.value.func.id
                    elif isinstance(node.value.func, ast.Attribute):
                        func_name = node.value.func.attr

                    if func_name and 'Mib' in func_name:
                        analysis['statistics']['mib_objects'] += 1
                        analysis['metadata']['mib_object_types'].append(func_name)

    # Determine if it looks like a MIB
    analysis['metadata']['looks_like_mib'] = (
        analysis['metadata']['has_pysnmp_imports'] and
        analysis['statistics']['mib_objects'] > 0
    )

    # Try to extract MIB name from content
    mib_name_match = re.search(r"mibBuilder\.export.*?['\"](\w+(?:-\w+)*)['\"]", content)
    if mib_name_match:
        analysis['metadata']['mib_name'] = mib_name_match.group(1)

    return analysis


def create_mib_summary_report(mib_directory: Path,
                            compiled_directory: Optional[Path] = None,
                            output_format: str = 'text') -> str:
    """Create a comprehensive summary report of MIB files and compilation"""

    # Analyze source MIBs
    analysis = analyze_mib_directory(mib_directory, include_dependencies=True, include_objects=True)

    if output_format == 'json':
        return json.dumps(analysis, indent=2, default=str)

    # Generate text report
    report = []
    report.append("=" * 80)
    report.append("MIB COMPREHENSIVE ANALYSIS REPORT")
    report.append("=" * 80)
    report.append(f"Generated: {analysis['timestamp']}")
    report.append(f"Source Directory: {analysis['directory']}")
    report.append("")

    # Summary section
    summary = analysis.get('summary', {})
    report.append("SUMMARY STATISTICS")
    report.append("-" * 20)
    report.append(f"Total MIB Files: {summary.get('total_files', 0)}")
    report.append(f"Total Size: {summary.get('total_size', 0):,} bytes")
    report.append(f"Total Object Types: {summary.get('total_objects', 0)}")
    report.append(f"Unique MIB Names: {summary.get('unique_mib_names', 0)}")
    report.append(f"Unique Dependencies: {summary.get('unique_dependencies', 0)}")
    report.append("")

    # Statistics section
    stats = analysis.get('statistics', {})
    report.append("FILE STATISTICS")
    report.append("-" * 15)
    report.append(f"Average File Size: {stats.get('average_file_size', 0):,.0f} bytes")
    report.append(f"Average Objects per MIB: {stats.get('average_objects_per_mib', 0):.1f}")

    file_exts = stats.get('file_extensions', {})
    for ext, count in file_exts.items():
        report.append(f"Files with {ext}: {count}")
    report.append("")

    # Individual MIB details
    mibs = analysis.get('mibs', [])
    valid_mibs = [mib for mib in mibs if 'error' not in mib]

    if valid_mibs:
        report.append("INDIVIDUAL MIB ANALYSIS")
        report.append("-" * 25)

        for mib in sorted(valid_mibs, key=lambda x: x.get('name', '')):
            name = mib.get('name', 'Unknown')
            size = mib.get('size', 0)
            obj_count = len(mib.get('object_types', []))
            dep_count = len(mib.get('dependencies', []))

            report.append(f"{name}:")
            report.append(f"  File: {Path(mib['file']).name}")
            report.append(f"  Size: {size:,} bytes")
            report.append(f"  Object Types: {obj_count}")
            report.append(f"  Notifications: {len(mib.get('notifications', []))}")
            report.append(f"  Textual Conventions: {len(mib.get('textual_conventions', []))}")
            report.append(f"  Dependencies: {dep_count}")

            if mib.get('dependencies'):
                deps = ', '.join(sorted(mib['dependencies']))
                report.append(f"  Imports from: {deps}")

            # Metadata
            metadata = mib.get('metadata', {})
            if metadata.get('organization'):
                report.append(f"  Organization: {metadata['organization']}")

            revisions = metadata.get('revisions', [])
            if revisions:
                latest = revisions[0]  # Assuming sorted by date
                report.append(f"  Latest Revision: {latest.get('date', 'Unknown')}")

            report.append("")

    # Dependency analysis
    dependencies = analysis.get('dependencies', {})
    if dependencies:
        report.append("DEPENDENCY ANALYSIS")
        report.append("-" * 18)
        report.append(f"Total Dependencies: {dependencies.get('total_dependencies', 0)}")
        report.append(f"Available Internally: {dependencies.get('available_internal', 0)}")
        report.append(f"Missing External: {dependencies.get('missing_external', 0)}")

        missing = dependencies.get('missing_list', [])
        if missing:
            report.append("\nMissing Dependencies:")
            for dep in sorted(missing):
                report.append(f"  - {dep}")
        report.append("")

    # Compilation analysis (if compiled directory provided)
    if compiled_directory and compiled_directory.exists():
        report.append("COMPILATION ANALYSIS")
        report.append("-" * 19)

        compiled_files = list(compiled_directory.glob("*.py"))
        report.append(f"Compiled Files: {len(compiled_files)}")

        if valid_mibs:
            success_rate = (len(compiled_files) / len(valid_mibs)) * 100
            report.append(f"Success Rate: {success_rate:.1f}%")

        total_compiled_size = sum(f.stat().st_size for f in compiled_files)
        report.append(f"Total Compiled Size: {total_compiled_size:,} bytes")

        # Validate compiled files
        valid_count = 0
        validation_warnings = 0

        for compiled_file in compiled_files:
            validation = validate_compiled_mib(compiled_file)
            if validation['valid']:
                valid_count += 1
            validation_warnings += len(validation['warnings'])

        report.append(f"Valid Compiled Files: {valid_count}/{len(compiled_files)}")
        report.append(f"Total Validation Warnings: {validation_warnings}")
        report.append("")

        # List compiled files
        if compiled_files:
            report.append("Compiled Files:")
            for py_file in sorted(compiled_files):
                size = py_file.stat().st_size
                report.append(f"  {py_file.stem:<30} {size:>8,} bytes")
            report.append("")

    # Error summary
    error_mibs = [mib for mib in mibs if 'error' in mib]
    if error_mibs:
        report.append("ERROR SUMMARY")
        report.append("-" * 13)
        report.append(f"Files with Errors: {len(error_mibs)}")
        for mib in error_mibs:
            report.append(f"  {Path(mib['file']).name}: {mib['error']}")
        report.append("")

    report.append("=" * 80)
    report.append("END OF REPORT")
    report.append("=" * 80)

    return '\n'.join(report)