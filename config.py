"""
Configuration management for MITRE ATT&CK Mapping Tool
Supports both .env files (local) and Streamlit secrets (cloud)
"""
import os
from typing import Optional

# Try to load from .env file (local development)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Try to load from Streamlit secrets (cloud deployment)
try:
    import streamlit as st
    if hasattr(st, 'secrets'):
        # Running in Streamlit with secrets available
        _use_streamlit_secrets = True
    else:
        _use_streamlit_secrets = False
except (ImportError, RuntimeError):
    _use_streamlit_secrets = False


def get_config_value(key: str, default: str = None) -> Optional[str]:
    """
    Get configuration value from environment or Streamlit secrets
    
    Args:
        key: Configuration key name
        default: Default value if not found
        
    Returns:
        Configuration value or default
    """
    # Try Streamlit secrets first (cloud deployment)
    if _use_streamlit_secrets:
        try:
            import streamlit as st
            return st.secrets.get(key, os.getenv(key, default))
        except Exception:
            pass
    
    # Fall back to environment variables (local development)
    return os.getenv(key, default)


class Config:
    """Application configuration settings"""
    
    # API Configuration
    CLAUDE_API_KEY: Optional[str] = get_config_value('CLAUDE_API_KEY')
    CLAUDE_MODEL: str = get_config_value('CLAUDE_MODEL', 'claude-haiku-4-5-20251001')
    
    # Similarity Thresholds
    SIMILARITY_THRESHOLD: float = float(get_config_value('SIMILARITY_THRESHOLD', '0.8'))
    CLAUDE_THRESHOLD: float = float(get_config_value('CLAUDE_THRESHOLD', '0.70'))
    
    # Processing Settings
    BATCH_SIZE: int = int(get_config_value('BATCH_SIZE', '32'))
    
    # Logging
    LOG_LEVEL: str = get_config_value('LOG_LEVEL', 'INFO')
    
    # MITRE ATT&CK Data Source
    MITRE_ATTACK_URL: str = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    
    # Tactic Priority Scores (for gap analysis)
    TACTIC_PRIORITY = {
        'initial-access': 10,
        'execution': 9,
        'persistence': 9,
        'privilege-escalation': 8,
        'defense-evasion': 8,
        'credential-access': 8,
        'discovery': 6,
        'lateral-movement': 7,
        'collection': 6,
        'command-and-control': 7,
        'exfiltration': 8,
        'impact': 9
    }
    
    # High Prevalence Techniques (commonly observed in the wild)
    HIGH_PREVALENCE_TECHNIQUES = {
        'T1059', 'T1053', 'T1055', 'T1003', 'T1078',
        'T1082', 'T1083', 'T1021', 'T1070', 'T1105',
        'T1027', 'T1204', 'T1071', 'T1569', 'T1562'
    }
    
    # Required CSV Columns
    REQUIRED_COLUMNS = ['Description']
    OPTIONAL_COLUMNS = ['Use Case Name', 'Log Source', 'Mapped MITRE Tactic(s)', 
                       'Mapped MITRE Technique(s)', 'Reference Resource(s)', 'Search']
    
    # Library CSV Path
    LIBRARY_CSV_PATH: str = "library.csv"
    
    @classmethod
    def validate(cls) -> bool:
        """Validate configuration settings"""
        if cls.SIMILARITY_THRESHOLD < 0 or cls.SIMILARITY_THRESHOLD > 1:
            raise ValueError("SIMILARITY_THRESHOLD must be between 0 and 1")
        if cls.CLAUDE_THRESHOLD < 0 or cls.CLAUDE_THRESHOLD > 1:
            raise ValueError("CLAUDE_THRESHOLD must be between 0 and 1")
        if cls.BATCH_SIZE < 1:
            raise ValueError("BATCH_SIZE must be at least 1")
        return True


# Validate configuration on import
Config.validate()
