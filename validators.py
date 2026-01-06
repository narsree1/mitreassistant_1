"""
Input validation functions for MITRE ATT&CK Mapping Tool
"""
import pandas as pd
import streamlit as st
from typing import Tuple, List, Optional
import logging

logger = logging.getLogger(__name__)


class CSVValidationError(Exception):
    """Custom exception for CSV validation errors"""
    pass


def validate_uploaded_csv(df: pd.DataFrame) -> Tuple[bool, Optional[str], pd.DataFrame]:
    """
    Comprehensive validation for uploaded CSV files.
    
    Args:
        df: Uploaded DataFrame to validate
        
    Returns:
        Tuple of (is_valid, error_message, sanitized_df)
    """
    try:
        # Check if DataFrame is empty
        if df.empty:
            return False, "The uploaded CSV file is empty.", df
        
        # Check for required columns
        required_columns = ['Description']
        missing_columns = [col for col in required_columns if col not in df.columns]
        
        if missing_columns:
            return False, f"Missing required column(s): {', '.join(missing_columns)}", df
        
        # Check if Description column has valid data
        valid_descriptions = df['Description'].notna() & (df['Description'] != '')
        if not valid_descriptions.any():
            return False, "The 'Description' column contains no valid data.", df
        
        # Sanitize the DataFrame
        df = sanitize_csv_data(df)
        
        # Check for reasonable data size
        if len(df) > 10000:
            logger.warning(f"Large CSV file detected: {len(df)} rows")
            st.warning(f"⚠️ Large file detected ({len(df)} rows). Processing may take longer.")
        
        # Validate data types
        for col in df.columns:
            if df[col].dtype == 'object':
                # Check for extremely long text fields
                max_length = df[col].astype(str).str.len().max()
                if max_length > 10000:
                    logger.warning(f"Column '{col}' contains very long text (max: {max_length} chars)")
        
        logger.info(f"CSV validation passed: {len(df)} rows, {len(df.columns)} columns")
        return True, None, df
        
    except Exception as e:
        logger.error(f"CSV validation error: {str(e)}")
        return False, f"Validation error: {str(e)}", df


def sanitize_csv_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Sanitize CSV data to prevent injection attacks and handle malformed data.
    
    Args:
        df: DataFrame to sanitize
        
    Returns:
        Sanitized DataFrame
    """
    df = df.copy()
    
    # Characters that could indicate CSV injection
    dangerous_prefixes = ['=', '+', '-', '@', '\t', '\r', '\n']
    
    for col in df.columns:
        if df[col].dtype == 'object':
            # Remove dangerous prefixes
            df[col] = df[col].apply(lambda x: sanitize_cell(x, dangerous_prefixes))
            
            # Strip whitespace
            df[col] = df[col].apply(lambda x: x.strip() if isinstance(x, str) else x)
    
    # Fill NaN values appropriately
    for col in df.columns:
        if df[col].dtype == 'object':
            df[col] = df[col].fillna('N/A')
    
    logger.info("CSV data sanitized")
    return df


def sanitize_cell(value, dangerous_prefixes: List[str]) -> str:
    """
    Sanitize individual cell value.
    
    Args:
        value: Cell value to sanitize
        dangerous_prefixes: List of dangerous prefix characters
        
    Returns:
        Sanitized cell value
    """
    if not isinstance(value, str):
        return value
    
    if not value:
        return value
    
    # Remove dangerous prefixes
    while value and value[0] in dangerous_prefixes:
        value = value[1:]
        logger.debug(f"Removed dangerous prefix from cell value")
    
    return value


def validate_api_key(api_key: Optional[str]) -> Tuple[bool, Optional[str]]:
    """
    Validate Claude API key format.
    
    Args:
        api_key: API key to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not api_key:
        return False, "API key is empty"
    
    # Basic format validation for Anthropic API keys
    if not api_key.startswith('sk-ant-'):
        return False, "API key should start with 'sk-ant-'"
    
    if len(api_key) < 20:
        return False, "API key appears to be too short"
    
    logger.info("API key format validation passed")
    return True, None


def validate_library_csv(df: pd.DataFrame) -> Tuple[bool, Optional[str]]:
    """
    Validate library CSV file structure.
    
    Args:
        df: Library DataFrame to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    required_columns = [
        'Use Case Name',
        'Description',
        'Log Source',
        'Mapped MITRE Tactic(s)',
        'Mapped MITRE Technique(s)'
    ]
    
    missing_columns = [col for col in required_columns if col not in df.columns]
    
    if missing_columns:
        return False, f"Library CSV missing required columns: {', '.join(missing_columns)}"
    
    if df.empty:
        return False, "Library CSV is empty"
    
    logger.info(f"Library CSV validation passed: {len(df)} entries")
    return True, None


def validate_threshold(threshold: float, name: str = "threshold") -> Tuple[bool, Optional[str]]:
    """
    Validate threshold value is between 0 and 1.
    
    Args:
        threshold: Threshold value to validate
        name: Name of the threshold for error messages
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(threshold, (int, float)):
        return False, f"{name} must be a number"
    
    if threshold < 0 or threshold > 1:
        return False, f"{name} must be between 0 and 1"
    
    return True, None
