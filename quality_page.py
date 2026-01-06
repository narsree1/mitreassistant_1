# quality_page.py - Data Quality Dashboard

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from quality_scorer import QualityScorer
import logging

logger = logging.getLogger(__name__)


def render_quality_page():
    """
    Render the Data Quality page with scoring and recommendations.
    """
    st.markdown("# 📊 Data Quality Assessment")
    
    if not st.session_state.mapping_complete or st.session_state.processed_data is None:
        st.info("Please complete the mapping process on the Home page first.")
        if st.button("Go to Home"):
            st.session_state.page = "home"
            st.rerun()
        return
    
    df = st.session_state.processed_data.copy()
    
    # Initialize quality scorer
    scorer = QualityScorer()
    
    # Check if quality scores already calculated
    if 'Quality Score' not in df.columns:
        with st.spinner("Analyzing data quality..."):
            df = scorer.score_dataframe(df)
            st.session_state.processed_data = df
            logger.info("Quality scores calculated and added to dataframe")
    
    # Get quality summary
    summary = scorer.get_quality_summary(df)
    
    # Display summary metrics
    st.markdown("### Quality Overview")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{summary['average_score']}</div>
            <div class="metric-label">Average Quality Score</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{summary['excellent_count']}</div>
            <div class="metric-label">🟢 Excellent (85+)</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{summary['good_count']}</div>
            <div class="metric-label">🟡 Good (70-84)</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{summary['needs_improvement']}</div>
            <div class="metric-label">⚠️ Needs Improvement</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Quality distribution chart
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Quality Distribution")
        
        # Pie chart of quality tiers
        tier_counts = df['Quality Tier'].value_counts()
        colors = {'Excellent': '#28a745', 'Good': '#ffc107', 'Fair': '#fd7e14', 'Poor': '#dc3545'}
        
        fig = go.Figure(data=[go.Pie(
            labels=tier_counts.index,
            values=tier_counts.values,
            marker=dict(colors=[colors.get(tier, '#6c757d') for tier in tier_counts.index]),
            hole=0.4
        )])
        
        fig.update_layout(
            showlegend=True,
            height=300,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### Score Components")
        
        # Average scores by component
        components = {
            'Description': df['Description Quality'].mean(),
            'Mapping': df['Mapping Quality'].mean(),
            'Completeness': df['Completeness'].mean()
        }
        
        fig = go.Figure(data=[go.Bar(
            x=list(components.keys()),
            y=list(components.values()),
            marker_color=['#007bff', '#17a2b8', '#6f42c1'],
            text=[f"{v:.1f}" for v in components.values()],
            textposition='auto'
        )])
        
        fig.update_layout(
            yaxis_title="Average Score",
            yaxis_range=[0, 100],
            height=300,
            margin=dict(l=20, r=20, t=40, b=20),
            showlegend=False
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    # Top quality issues
    if summary.get('top_issues'):
        st.markdown("### 🔍 Most Common Quality Issues")
        
        issues_df = pd.DataFrame(summary['top_issues'], columns=['Issue', 'Count'])
        
        fig = go.Figure(data=[go.Bar(
            x=issues_df['Count'],
            y=issues_df['Issue'],
            orientation='h',
            marker_color='#dc3545',
            text=issues_df['Count'],
            textposition='auto'
        )])
        
        fig.update_layout(
            xaxis_title="Number of Use Cases",
            height=max(250, len(issues_df) * 40),
            margin=dict(l=20, r=20, t=20, b=20),
            showlegend=False
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    
    # Filter options
    st.markdown("### 📋 Use Case Quality Details")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        tier_filter = st.multiselect(
            "Filter by Quality Tier",
            options=['Excellent', 'Good', 'Fair', 'Poor'],
            default=['Excellent', 'Good', 'Fair', 'Poor']
        )
    
    with col2:
        min_score = st.slider("Minimum Quality Score", 0, 100, 0)
    
    with col3:
        sort_by = st.selectbox(
            "Sort by",
            options=['Quality Score', 'Description Quality', 'Mapping Quality', 'Completeness'],
            index=0
        )
    
    # Apply filters
    filtered_df = df[df['Quality Tier'].isin(tier_filter)]
    filtered_df = filtered_df[filtered_df['Quality Score'] >= min_score]
    filtered_df = filtered_df.sort_values(sort_by, ascending=False)
    
    st.info(f"Showing {len(filtered_df)} of {len(df)} use cases")
    
    # Display detailed table
    display_columns = [
        'Quality Tier Icon',
        'Use Case Name',
        'Quality Score',
        'Description Quality',
        'Mapping Quality',
        'Completeness',
        'Quality Recommendations'
    ]
    
    # Ensure all columns exist
    available_columns = [col for col in display_columns if col in filtered_df.columns]
    
    if available_columns:
        display_df = filtered_df[available_columns].copy()
        
        # Format scores
        for col in ['Quality Score', 'Description Quality', 'Mapping Quality', 'Completeness']:
            if col in display_df.columns:
                display_df[col] = display_df[col].apply(lambda x: f"{x:.1f}")
        
        st.dataframe(
            display_df,
            use_container_width=True,
            height=400,
            column_config={
                "Quality Tier Icon": st.column_config.TextColumn("", width="small"),
                "Use Case Name": st.column_config.TextColumn("Use Case", width="medium"),
                "Quality Score": st.column_config.TextColumn("Overall", width="small"),
                "Description Quality": st.column_config.TextColumn("Description", width="small"),
                "Mapping Quality": st.column_config.TextColumn("Mapping", width="small"),
                "Completeness": st.column_config.TextColumn("Complete", width="small"),
                "Quality Recommendations": st.column_config.TextColumn("Recommendations", width="large")
            }
        )
    
    # Export options
    st.markdown("---")
    st.markdown("### 📥 Export Quality Report")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Export full quality report
        csv_data = df.to_csv(index=False)
        st.download_button(
            label="📊 Download Full Quality Report (CSV)",
            data=csv_data,
            file_name="quality_report.csv",
            mime="text/csv"
        )
    
    with col2:
        # Export only low-quality items
        low_quality = df[df['Quality Score'] < 70]
        if not low_quality.empty:
            csv_low = low_quality.to_csv(index=False)
            st.download_button(
                label="⚠️ Download Items Needing Improvement (CSV)",
                data=csv_low,
                file_name="needs_improvement.csv",
                mime="text/csv"
            )
        else:
            st.success("✅ All use cases have good quality!")
    
    # Quality improvement tips
    with st.expander("💡 Tips for Improving Quality Scores"):
        st.markdown("""
        ### Description Quality
        - **Length**: Aim for 50-300 characters - detailed but concise
        - **Keywords**: Include detection-specific terms (detect, monitor, alert, identify)
        - **Technical Details**: Mention specific artifacts (process, registry, network, file)
        - **Structure**: Use multiple sentences to explain what, why, and how
        - **Specificity**: Avoid vague terms like "various", "multiple", "different"
        
        ### Mapping Quality
        - **Technique Format**: Always include MITRE ID (e.g., "T1059 - Command and Scripting Interpreter")
        - **Tactic Accuracy**: Ensure tactic names match MITRE framework
        - **Confidence**: Higher confidence scores indicate better matches
        - **Review Low Confidence**: Manually review mappings with confidence < 70%
        
        ### Completeness
        - **Required Fields**: Ensure all required fields are filled
        - **Log Sources**: Specify the data sources needed
        - **References**: Add links to documentation or detection rules
        - **Search Queries**: Include sample search/detection logic when possible
        
        ### Best Practices
        1. Start with high-quality descriptions - they lead to better mappings
        2. Review and refine low-scoring use cases first
        3. Use the library as examples of well-documented use cases
        4. Regularly assess quality as you add new use cases
        5. Aim for an average quality score above 75
        """)
