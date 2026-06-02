"""
LIDRA v3 YAML Rules Engine

Loads and executes detection rules from YAML files.
Sigma-compatible format with LIDRA extensions.
"""

import re
import logging
import glob
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import yaml

logger = logging.getLogger(__name__)


@dataclass
class DetectionRule:
    """Detection rule from YAML."""
    id: str
    name: str
    severity: str
    category: str
    description: str
    condition: Dict
    mitre: List[str]
    actions: List[str]
    enabled: bool = True


class RuleLoader:
    """
    Loads and manages YAML detection rules.
    
    Supports:
    - Sigma rule format (subset)
    - LIDRA-specific extensions
    - Hot-reload without restart
    """
    
    def __init__(self, rules_dir: str = None):
        self.rules_dir = rules_dir
        self.rules: Dict[str, DetectionRule] = {}
        self.rule_files: Dict[str, float] = {}
        
        if rules_dir:
            self._load_all_rules(rules_dir)
    
    def _load_all_rules(self, rules_dir: str):
        """Load all YAML rules from directory."""
        path = Path(rules_dir)
        
        if not path.exists():
            logger.warning(f"Rules directory not found: {rules_dir}")
            return
        
        for yaml_file in path.glob("*.yaml"):
            self._load_file(yaml_file)
    
    def _load_file(self, yaml_file: Path):
        """Load rules from a single YAML file."""
        try:
            with open(yaml_file, 'r') as f:
                data = yaml.safe_load(f)
            
            rules = data.get('rules', [])
            
            for rule_data in rules:
                if not rule_data.get('enabled', True):
                    continue
                
                rule = DetectionRule(
                    id=rule_data.get('id', ''),
                    name=rule_data.get('name', ''),
                    severity=rule_data.get('severity', 'medium'),
                    category=rule_data.get('category', 'unknown'),
                    description=rule_data.get('description', ''),
                    condition=rule_data.get('condition', {}),
                    mitre=rule_data.get('mitre', []),
                    actions=rule_data.get('actions', ['alert']),
                    enabled=rule_data.get('enabled', True)
                )
                
                if rule.id:
                    self.rules[rule.id] = rule
            
            self.rule_files[str(yaml_file)] = yaml_file.stat().st_mtime
            logger.info(f"Loaded {len(rules)} rules from {yaml_file.name}")
            
        except Exception as e:
            logger.error(f"Error loading {yaml_file}: {e}")
    
    def reload(self):
        """Hot-reload rules that have changed."""
        if not self.rules_dir:
            return
        
        path = Path(self.rules_dir)
        
        for yaml_file in path.glob("*.yaml"):
            mtime = yaml_file.stat().st_mtime
            prev_mtime = self.rule_files.get(str(yaml_file), 0)
            
            if mtime > prev_mtime:
                logger.info(f"Reloading {yaml_file.name}")
                self._load_file(yaml_file)
    
    def match(self, event: Dict) -> List[DetectionRule]:
        """
        Check if event matches any rules.
        
        Args:
            event: Security event dictionary
            
        Returns:
            List of matched rules
        """
        matched = []
        
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            
            if self._match_condition(rule.condition, event):
                matched.append(rule)
        
        return matched
    
    def _match_condition(self, condition: Dict, event: Dict) -> bool:
        """Check if event matches rule condition."""
        condition_type = condition.get('type', 'pattern')
        
        if condition_type == 'pattern':
            return self._match_pattern(condition, event)
        
        elif condition_type == 'field':
            return self._match_field(condition, event)
        
        elif condition_type == 'composite':
            return self._match_composite(condition, event)
        
        return False
    
    def _match_pattern(self, condition: Dict, event: Dict) -> bool:
        """Match against regex pattern."""
        pattern = condition.get('pattern', '')
        field = condition.get('field', 'raw_line')
        
        value = event.get(field, '')
        
        if isinstance(value, list):
            value = ' '.join(str(v) for v in value)
        
        try:
            return bool(re.search(pattern, str(value), re.IGNORECASE))
        except re.error:
            return False
    
    def _match_field(self, condition: Dict, event: Dict) -> bool:
        """Match against field value."""
        field = condition.get('field', '')
        operator = condition.get('operator', 'equals')
        value = condition.get('value', '')
        
        event_value = self._get_nested_field(event, field)
        
        if operator == 'equals':
            return str(event_value) == str(value)
        elif operator == 'contains':
            return value in str(event_value)
        elif operator == 'startswith':
            return str(event_value).startswith(value)
        elif operator == 'endswith':
            return str(event_value).endswith(value)
        elif operator == 'gt':
            return float(event_value or 0) > float(value)
        elif operator == 'lt':
            return float(event_value or 0) < float(value)
        elif operator == 'in':
            return event_value in value.split(',')
        
        return False
    
    def _match_composite(self, condition: Dict, event: Dict) -> bool:
        """Match composite (AND/OR) conditions."""
        logic = condition.get('logic', 'and')
        subconditions = condition.get('conditions', [])
        
        if logic == 'and':
            return all(self._match_condition(c, event) for c in subconditions)
        elif logic == 'or':
            return any(self._match_condition(c, event) for c in subconditions)
        
        return False
    
    def _get_nested_field(self, data: Dict, field: str) -> Any:
        """Get nested field using dot notation."""
        keys = field.split('.')
        value = data
        
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            elif isinstance(value, list) and key.isdigit():
                value = value[int(key)]
            else:
                return None
        
        return value
    
    def get_rules_by_category(self, category: str) -> List[DetectionRule]:
        """Get all rules for a category."""
        return [r for r in self.rules.values() if r.category == category]
    
    def get_rules_by_severity(self, severity: str) -> List[DetectionRule]:
        """Get all rules for a severity level."""
        return [r for r in self.rules.values() if r.severity == severity]
    
    def get_rule_count(self) -> int:
        """Get total rule count."""
        return len(self.rules)


def create_rule_loader(rules_dir: str = None) -> RuleLoader:
    """Factory function."""
    return RuleLoader(rules_dir)