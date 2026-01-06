"""
Utility functions for MITRE ATT&CK Mapping Tool
"""
import pandas as pd
import logging
from typing import Dict, List, Tuple, Optional
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def normalize_tactic(tactic: str) -> str:
    """
    Normalize tactic names to a standard format.
    
    Args:
        tactic: Raw tactic name from various sources
        
    Returns:
        Normalized tactic name in standard format
    """
    if not tactic or tactic == 'N/A':
        return tactic
    
    tactic_lower = tactic.lower()
    
    tactic_mapping = {
        'command': 'Command and Control',
        'persistence': 'Persistence',
        'discovery': 'Discovery',
        'execution': 'Execution',
        'privilege': 'Privilege Escalation',
        'defense': 'Defense Evasion',
        'credential': 'Credential Access',
        'lateral': 'Lateral Movement',
        'collection': 'Collection',
        'exfiltration': 'Exfiltration',
        'impact': 'Impact',
        'initial': 'Initial Access'
    }
    
    for key, value in tactic_mapping.items():
        if key in tactic_lower:
            return value
    
    return tactic[0].upper() + tactic[1:] if len(tactic) > 0 else tactic


def count_techniques(df: pd.DataFrame, 
                     mitre_techniques: List[Dict]) -> Dict[str, int]:
    """
    Count occurrences of each MITRE technique in the dataframe.
    Handles comma-separated techniques and various formats.
    
    Args:
        df: DataFrame containing mapped techniques
        mitre_techniques: List of MITRE technique dictionaries
        
    Returns:
        Dictionary mapping technique IDs to their counts
    """
    technique_count = {}
    technique_name_mapping = {}
    
    # Create technique ID to name mapping
    for tech in mitre_techniques:
        technique_name_mapping[tech['id']] = tech['name']
    
    # Process each row
    for _, row in df.iterrows():
        technique_str = row.get('Mapped MITRE Technique(s)', '')
        if pd.isna(technique_str) or technique_str == 'N/A':
            continue
        
        # Handle comma-separated techniques
        techniques = [t.strip() for t in str(technique_str).split(',')]
        
        for technique in techniques:
            if not technique:
                continue
            
            # Extract ID if in "T1234 - Name" format
            if ' - ' in technique and technique.startswith('T'):
                tech_id = technique.split(' - ')[0].strip()
            else:
                # Look up by name
                tech_name = technique
                tech_id = None
                
                for tid, tname in technique_name_mapping.items():
                    if tname.lower() == tech_name.lower():
                        tech_id = tid
                        break
                
                if not tech_id:
                    tech_id = tech_name
            
            technique_count[tech_id] = technique_count.get(tech_id, 0) + 1
    
    logger.info(f"Counted {len(technique_count)} unique techniques")
    return technique_count


def validate_csv_schema(df: pd.DataFrame, 
                       required_columns: List[str],
                       optional_columns: List[str] = None) -> Tuple[bool, List[str]]:
    """
    Validate that a CSV DataFrame has the required schema.
    
    Args:
        df: DataFrame to validate
        required_columns: List of required column names
        optional_columns: List of optional column names
        
    Returns:
        Tuple of (is_valid, list_of_missing_columns)
    """
    missing_columns = []
    
    for col in required_columns:
        if col not in df.columns:
            missing_columns.append(col)
    
    is_valid = len(missing_columns) == 0
    
    if is_valid:
        logger.info("CSV schema validation passed")
    else:
        logger.warning(f"CSV schema validation failed. Missing columns: {missing_columns}")
    
    return is_valid, missing_columns


def sanitize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Sanitize DataFrame to prevent CSV injection and handle malformed data.
    
    Args:
        df: DataFrame to sanitize
        
    Returns:
        Sanitized DataFrame
    """
    df = df.copy()
    
    # Replace potentially dangerous characters at the start of cells
    dangerous_chars = ['=', '+', '-', '@', '\t', '\r']
    
    for col in df.columns:
        if df[col].dtype == 'object':
            df[col] = df[col].apply(
                lambda x: str(x).lstrip(''.join(dangerous_chars)) 
                if isinstance(x, str) and x and x[0] in dangerous_chars 
                else x
            )
    
    logger.info("DataFrame sanitized successfully")
    return df


def create_cache_key(text: str, model_name: str = "") -> str:
    """
    Create a cache key for API responses.
    
    Args:
        text: Input text to cache
        model_name: Model name used for the request
        
    Returns:
        MD5 hash as cache key
    """
    cache_string = f"{text}_{model_name}"
    return hashlib.md5(cache_string.encode()).hexdigest()


def extract_technique_id(technique_str: str, 
                        technique_name_mapping: Dict[str, str]) -> Optional[str]:
    """
    Extract technique ID from various formats.
    
    Args:
        technique_str: Technique string in various formats
        technique_name_mapping: Mapping of technique IDs to names
        
    Returns:
        Extracted technique ID or None
    """
    if not technique_str or pd.isna(technique_str):
        return None
    
    technique_str = str(technique_str).strip()
    
    # Format: "T1234 - Name"
    if ' - ' in technique_str and technique_str.startswith('T'):
        return technique_str.split(' - ')[0].strip()
    
    # Format: "T1234"
    if technique_str.startswith('T') and technique_str[1:5].isdigit():
        return technique_str
    
    # Format: "Name" - lookup by name
    for tech_id, tech_name in technique_name_mapping.items():
        if tech_name.lower() == technique_str.lower():
            return tech_id
    
    return None


def format_confidence_score(score: float) -> str:
    """
    Format confidence score for display.
    
    Args:
        score: Confidence score (0-1 or 0-100)
        
    Returns:
        Formatted string with percentage
    """
    if score <= 1:
        score = score * 100
    return f"{score:.1f}%"


def get_parent_techniques(mitre_techniques: List[Dict]) -> List[Dict]:
    """
    Filter MITRE techniques to only include parent techniques (no sub-techniques).
    
    Args:
        mitre_techniques: List of all MITRE technique dictionaries
        
    Returns:
        List of parent technique dictionaries only
    """
    parent_techniques = []
    
    for tech in mitre_techniques:
        tech_id = tech.get('id', '')
        # Only include if ID starts with 'T', has no dot, and is not 'N/A'
        if tech_id.startswith('T') and '.' not in tech_id and tech_id != 'N/A':
            parent_techniques.append(tech)
    
    logger.info(f"Filtered to {len(parent_techniques)} parent techniques")
    return parent_techniques


def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """
    Safely divide two numbers, returning default if denominator is zero.
    
    Args:
        numerator: Numerator value
        denominator: Denominator value
        default: Default value to return if division by zero
        
    Returns:
        Result of division or default value
    """
    if denominator == 0:
        return default
    return numerator / denominator
