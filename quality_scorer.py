# quality_scorer.py - Data Quality Scoring Module

import pandas as pd
import re
from typing import Dict, Tuple, List
import logging

logger = logging.getLogger(__name__)


class QualityScorer:
    """
    Evaluates the quality of use case descriptions and MITRE mappings.
    Provides scores and recommendations for improvement.
    """
    
    def __init__(self):
        # Quality criteria weights
        self.weights = {
            'description_length': 0.15,
            'description_detail': 0.20,
            'technique_specificity': 0.25,
            'confidence_score': 0.20,
            'completeness': 0.20
        }
        
        # Keywords indicating detailed descriptions
        self.detail_keywords = [
            'detect', 'monitor', 'alert', 'identify', 'analyze', 'track',
            'suspicious', 'malicious', 'unauthorized', 'anomalous',
            'baseline', 'threshold', 'correlation', 'pattern',
            'event', 'log', 'activity', 'behavior', 'indicator'
        ]
        
        # Technical terms indicating quality
        self.technical_terms = [
            'process', 'registry', 'network', 'file', 'service', 'user',
            'command', 'script', 'execution', 'authentication', 'privilege',
            'lateral', 'persistence', 'exfiltration', 'payload'
        ]
    
    def score_description(self, description: str) -> Tuple[float, List[str]]:
        """
        Score the quality of a use case description.
        
        Args:
            description: Use case description text
            
        Returns:
            Tuple of (score 0-100, list of recommendations)
        """
        if pd.isna(description) or not description or description == "N/A":
            return 0.0, ["Missing description"]
        
        desc_lower = str(description).lower()
        recommendations = []
        scores = []
        
        # 1. Length check (20-500 chars is good)
        length = len(description)
        if length < 20:
            length_score = length / 20 * 100
            recommendations.append("Description too short - add more details")
        elif length > 500:
            length_score = 100 - ((length - 500) / 10)
            length_score = max(70, length_score)
            recommendations.append("Description very long - consider being more concise")
        else:
            length_score = 100
        scores.append(length_score)
        
        # 2. Detail keywords (indicates thoughtful description)
        detail_count = sum(1 for keyword in self.detail_keywords if keyword in desc_lower)
        detail_score = min(100, (detail_count / 3) * 100)
        if detail_count < 2:
            recommendations.append("Add more detection-specific keywords (e.g., 'detect', 'monitor', 'alert')")
        scores.append(detail_score)
        
        # 3. Technical terms (indicates specificity)
        tech_count = sum(1 for term in self.technical_terms if term in desc_lower)
        tech_score = min(100, (tech_count / 2) * 100)
        if tech_count < 1:
            recommendations.append("Include technical details (e.g., 'process', 'registry', 'network')")
        scores.append(tech_score)
        
        # 4. Sentence structure (multiple sentences is better)
        sentences = len([s for s in re.split(r'[.!?]+', description) if s.strip()])
        structure_score = min(100, (sentences / 2) * 100)
        if sentences < 2:
            recommendations.append("Expand description with multiple sentences")
        scores.append(structure_score)
        
        # 5. Avoid generic phrases
        generic_phrases = ['various', 'multiple', 'different', 'several', 'some']
        generic_count = sum(1 for phrase in generic_phrases if phrase in desc_lower)
        generic_score = max(0, 100 - (generic_count * 20))
        if generic_count > 2:
            recommendations.append("Reduce vague terms - be more specific")
        scores.append(generic_score)
        
        # Calculate weighted average
        final_score = sum(scores) / len(scores)
        
        return round(final_score, 1), recommendations
    
    def score_mapping(self, technique: str, tactic: str, confidence: float) -> Tuple[float, List[str]]:
        """
        Score the quality of a MITRE mapping.
        
        Args:
            technique: Mapped MITRE technique
            tactic: Mapped MITRE tactic
            confidence: Confidence score (0-100)
            
        Returns:
            Tuple of (score 0-100, list of recommendations)
        """
        recommendations = []
        scores = []
        
        # 1. Technique specificity (has ID format)
        if pd.isna(technique) or technique == "N/A":
            scores.append(0)
            recommendations.append("No technique mapped")
        elif technique.startswith('T') and '-' in technique:
            scores.append(100)
        elif technique.startswith('T'):
            scores.append(80)
            recommendations.append("Technique ID present but format unclear")
        else:
            scores.append(50)
            recommendations.append("Technique should include ID (e.g., T1234)")
        
        # 2. Tactic validity
        valid_tactics = [
            'reconnaissance', 'resource-development', 'initial-access', 'execution',
            'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
            'discovery', 'lateral-movement', 'collection', 'command-and-control',
            'exfiltration', 'impact'
        ]
        if pd.isna(tactic) or tactic == "N/A":
            scores.append(0)
            recommendations.append("No tactic mapped")
        elif any(vt in str(tactic).lower() for vt in valid_tactics):
            scores.append(100)
        else:
            scores.append(50)
            recommendations.append("Tactic name may be incorrect")
        
        # 3. Confidence score
        if confidence >= 90:
            scores.append(100)
        elif confidence >= 80:
            scores.append(90)
        elif confidence >= 70:
            scores.append(70)
            recommendations.append("Moderate confidence - consider manual review")
        elif confidence >= 60:
            scores.append(50)
            recommendations.append("Low confidence - manual review recommended")
        else:
            scores.append(30)
            recommendations.append("Very low confidence - mapping may be incorrect")
        
        final_score = sum(scores) / len(scores)
        return round(final_score, 1), recommendations
    
    def score_completeness(self, row: pd.Series) -> Tuple[float, List[str]]:
        """
        Score the completeness of a use case entry.
        
        Args:
            row: DataFrame row with use case data
            
        Returns:
            Tuple of (score 0-100, list of recommendations)
        """
        recommendations = []
        required_fields = ['Use Case Name', 'Description', 'Log Source', 
                          'Mapped MITRE Tactic(s)', 'Mapped MITRE Technique(s)']
        optional_fields = ['Reference Resource(s)', 'Search']
        
        # Check required fields
        missing_required = []
        for field in required_fields:
            if field not in row or pd.isna(row[field]) or row[field] == "N/A":
                missing_required.append(field)
        
        required_score = ((len(required_fields) - len(missing_required)) / len(required_fields)) * 100
        
        if missing_required:
            recommendations.append(f"Missing required fields: {', '.join(missing_required)}")
        
        # Check optional fields
        missing_optional = []
        for field in optional_fields:
            if field not in row or pd.isna(row[field]) or row[field] == "N/A":
                missing_optional.append(field)
        
        optional_score = ((len(optional_fields) - len(missing_optional)) / len(optional_fields)) * 100
        
        if missing_optional:
            recommendations.append(f"Consider adding: {', '.join(missing_optional)}")
        
        # Weighted score (required fields are more important)
        final_score = (required_score * 0.8) + (optional_score * 0.2)
        
        return round(final_score, 1), recommendations
    
    def calculate_overall_quality(self, row: pd.Series) -> Dict:
        """
        Calculate overall quality score for a use case.
        
        Args:
            row: DataFrame row with use case data
            
        Returns:
            Dictionary with scores and recommendations
        """
        # Score each component
        desc_score, desc_recs = self.score_description(row.get('Description', ''))
        
        mapping_score, mapping_recs = self.score_mapping(
            row.get('Mapped MITRE Technique(s)', 'N/A'),
            row.get('Mapped MITRE Tactic(s)', 'N/A'),
            row.get('Confidence Score', 0)
        )
        
        completeness_score, completeness_recs = self.score_completeness(row)
        
        # Calculate weighted overall score
        overall_score = (
            desc_score * 0.4 +
            mapping_score * 0.4 +
            completeness_score * 0.2
        )
        
        # Determine quality tier
        if overall_score >= 85:
            tier = "Excellent"
            tier_color = "🟢"
        elif overall_score >= 70:
            tier = "Good"
            tier_color = "🟡"
        elif overall_score >= 50:
            tier = "Fair"
            tier_color = "🟠"
        else:
            tier = "Poor"
            tier_color = "🔴"
        
        # Combine all recommendations
        all_recommendations = desc_recs + mapping_recs + completeness_recs
        
        return {
            'overall_score': round(overall_score, 1),
            'tier': tier,
            'tier_color': tier_color,
            'description_score': desc_score,
            'mapping_score': mapping_score,
            'completeness_score': completeness_score,
            'recommendations': all_recommendations[:5]  # Top 5 recommendations
        }
    
    def score_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Score all use cases in a DataFrame.
        
        Args:
            df: DataFrame with use case data
            
        Returns:
            DataFrame with quality scores added
        """
        logger.info(f"Scoring quality for {len(df)} use cases...")
        
        results = []
        for idx, row in df.iterrows():
            quality = self.calculate_overall_quality(row)
            results.append(quality)
        
        # Add quality columns to dataframe
        df['Quality Score'] = [r['overall_score'] for r in results]
        df['Quality Tier'] = [r['tier'] for r in results]
        df['Quality Tier Icon'] = [r['tier_color'] for r in results]
        df['Description Quality'] = [r['description_score'] for r in results]
        df['Mapping Quality'] = [r['mapping_score'] for r in results]
        df['Completeness'] = [r['completeness_score'] for r in results]
        df['Quality Recommendations'] = ['; '.join(r['recommendations']) if r['recommendations'] else 'No recommendations' 
                                         for r in results]
        
        logger.info(f"Quality scoring complete. Average score: {df['Quality Score'].mean():.1f}")
        
        return df
    
    def get_quality_summary(self, df: pd.DataFrame) -> Dict:
        """
        Get summary statistics for quality scores.
        
        Args:
            df: DataFrame with quality scores
            
        Returns:
            Dictionary with summary statistics
        """
        if 'Quality Score' not in df.columns:
            return {}
        
        return {
            'average_score': round(df['Quality Score'].mean(), 1),
            'median_score': round(df['Quality Score'].median(), 1),
            'excellent_count': len(df[df['Quality Score'] >= 85]),
            'good_count': len(df[(df['Quality Score'] >= 70) & (df['Quality Score'] < 85)]),
            'fair_count': len(df[(df['Quality Score'] >= 50) & (df['Quality Score'] < 70)]),
            'poor_count': len(df[df['Quality Score'] < 50]),
            'needs_improvement': len(df[df['Quality Score'] < 70]),
            'top_issues': self._get_top_issues(df)
        }
    
    def _get_top_issues(self, df: pd.DataFrame, top_n: int = 5) -> List[Tuple[str, int]]:
        """Get most common quality issues"""
        if 'Quality Recommendations' not in df.columns:
            return []
        
        all_recs = []
        for recs in df['Quality Recommendations']:
            if recs and recs != 'No recommendations':
                all_recs.extend([r.strip() for r in str(recs).split(';')])
        
        # Count occurrences
        from collections import Counter
        rec_counts = Counter(all_recs)
        
        return rec_counts.most_common(top_n)
