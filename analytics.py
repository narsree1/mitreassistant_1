# analytics.py - MITRE ATT&CK Analytics Module

import pandas as pd
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import logging
from utils import normalize_tactic, count_techniques, get_parent_techniques, safe_divide

logger = logging.getLogger(__name__)

def render_analytics_page(mitre_techniques):
    """
    Self-contained analytics page with fixes for tactic normalization
    and technique splitting
    """
    st.markdown("# 📈 Coverage Analytics")
    
    if st.session_state.mapping_complete and st.session_state.processed_data is not None:
        df = st.session_state.processed_data
        
        # Key metrics
        col1, col2, col3, col4 = st.columns(4)
        
        # Use centralized technique counting logic
        logger.info("Processing technique counts for analytics...")
        processed_techniques_count = count_techniques(df, mitre_techniques)
        
        # Update session state for other pages
        st.session_state.techniques_count = processed_techniques_count
        
        # Create technique ID to name mapping
        technique_name_mapping = {tech['id']: tech['name'] for tech in mitre_techniques}
        
        # Calculate total parent techniques using centralized utility
        parent_techniques = get_parent_techniques(mitre_techniques)
        total_techniques = len(parent_techniques)
        
        covered_techniques = len(processed_techniques_count.keys())
        coverage_percent = round(safe_divide(covered_techniques, total_techniques, 0) * 100, 2)
        logger.info(f"Coverage: {covered_techniques}/{total_techniques} techniques ({coverage_percent}%)")
        
        # Count library matches vs model matches - handle NaN values safely
        library_matches = df[df['Match Source'].fillna('Unknown').astype(str).str.contains('library', case=False, na=False)].shape[0]
        model_matches = df[df['Match Source'].fillna('Unknown').astype(str).str.contains('Model', case=False, na=False)].shape[0]
        logger.info(f"Match sources - Library: {library_matches}, Model: {model_matches}")
        
        with col1:
            st.markdown("""
            <div class="metric-card">
                <div class="metric-value">{}</div>
                <div class="metric-label">Security Use Cases</div>
            </div>
            """.format(len(df)), unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="metric-card">
                <div class="metric-value">{}</div>
                <div class="metric-label">Mapped Techniques</div>
            </div>
            """.format(covered_techniques), unsafe_allow_html=True)
        
        with col3:
            st.markdown("""
            <div class="metric-card">
                <div class="metric-value">{}%</div>
                <div class="metric-label">Framework Coverage</div>
            </div>
            """.format(coverage_percent), unsafe_allow_html=True)
        
        with col4:
            st.markdown("""
            <div class="metric-card">
                <div class="metric-value">{} / {}</div>
                <div class="metric-label">Library Matches / Model Matches</div>
            </div>
            """.format(library_matches, model_matches), unsafe_allow_html=True)
        
        # Match source chart
        st.markdown("### Mapping Source Distribution")
        
        # Handle empty or all-NaN columns
        if not df['Match Source'].isna().all():
            match_source_counts = df['Match Source'].fillna('Unknown').value_counts().reset_index()
            match_source_counts.columns = ['Source', 'Count']
            
            # Create chart only if there's data
            if not match_source_counts.empty:
                fig_source = px.pie(
                    match_source_counts, 
                    values='Count', 
                    names='Source',
                    title="Distribution of Mapping Sources",
                    hole=0.5,
                    color_discrete_sequence=px.colors.qualitative.Set3
                )
                
                fig_source.update_layout(
                    legend=dict(orientation="h", yanchor="bottom", y=-0.2)
                )
                st.plotly_chart(fig_source, use_container_width=True)
            else:
                st.info("No mapping source data available for visualization.")
        else:
            st.info("No mapping source data available for visualization.")
        
        # Coverage by Tactic - Doughnut Chart with better color scheme
        st.markdown("### Coverage by Tactic")
        
        # Create data for tactic coverage - with normalization to fix duplicates
        tactic_counts = {}
        for _, row in df.iterrows():
            tactic_str = row.get('Mapped MITRE Tactic(s)', '')
            if pd.isna(tactic_str) or tactic_str == 'N/A':
                continue
                
            # Split and normalize each tactic to avoid duplicates
            for tactic in str(tactic_str).split(','):
                tactic = tactic.strip()
                if tactic and tactic != 'N/A':
                    # Normalize the tactic name to avoid duplicates
                    normalized_tactic = normalize_tactic(tactic)
                    tactic_counts[normalized_tactic] = tactic_counts.get(normalized_tactic, 0) + 1
        
        # Transform to dataframe for visualization
        tactic_df = pd.DataFrame({
            'Tactic': list(tactic_counts.keys()),
            'Use Cases': list(tactic_counts.values())
        }).sort_values('Use Cases', ascending=False)
        
        if not tactic_df.empty:
            # Create doughnut chart for tactic coverage with better colors
            fig_tactic = go.Figure(data=[go.Pie(
                labels=tactic_df['Tactic'],
                values=tactic_df['Use Cases'],
                hole=.5,
                textposition='outside',  # Modified: This ensures all labels are outside
                textinfo='label+percent',
                marker=dict(colors=px.colors.qualitative.Dark24)  # Using Dark24 for better contrast
            )])
            
            fig_tactic.update_layout(
                title="Security Use Cases by MITRE Tactic",
                showlegend=False,  # Remove legend to prevent overlap
                margin=dict(t=50, b=50, l=100, r=100)  # Added: Margin for external labels
            )
            
            st.plotly_chart(fig_tactic, use_container_width=True)
        else:
            st.info("No tactic data available for visualization.")
        
        # Coverage by Technique - Doughnut Chart with better naming
        st.markdown("### Coverage by Technique")
        
        if processed_techniques_count:
            # Get top techniques for the chart (limiting to top 10 for readability)
            technique_ids = list(processed_techniques_count.keys())
            technique_counts = list(processed_techniques_count.values())
            
            # Get technique names - with improved formatting
            technique_names = []
            for tech_id in technique_ids:
                # Find the technique name using the mapping
                tech_name = technique_name_mapping.get(tech_id, tech_id)
                technique_names.append(tech_name)
            
            technique_df = pd.DataFrame({
                'Technique': technique_names,
                'Count': technique_counts
            }).sort_values('Count', ascending=False).head(10)
            
            # Create doughnut chart for technique coverage with better colors
            fig_tech = go.Figure(data=[go.Pie(
                labels=technique_df['Technique'],
                values=technique_df['Count'],
                hole=.5,
                textposition='outside',  # Modified: This ensures all labels are outside
                textinfo='label+percent',
                marker=dict(colors=px.colors.qualitative.Bold)  # Using Bold color scheme for better contrast
            )])
            
            fig_tech.update_layout(
                title="Top 10 MITRE Techniques in Security Use Cases",
                showlegend=False,  # Remove legend to prevent overlap
                margin=dict(t=50, b=50, l=100, r=100)  # Added: Margin for external labels
            )
            
            st.plotly_chart(fig_tech, use_container_width=True)
        else:
            st.info("No technique data available for visualization.")
    
    else:
        st.info("No analytics data available. Please upload a CSV file on the Home page and complete the mapping process.")
        
        # Add a button to navigate back to home
        if st.button("Go to Home"):
            st.session_state.page = "home"
            st.experimental_rerun()
