# This is basic streamlit app to find the Bruteforce attack and other login attempts.
# Helpful to Security Admins who are spending mssive time to find attack vectors.



#-----Import Items Section-----#
import streamlit as st
import pandas as pd
import re
import matplotlib.pyplot as plt

#-----Page layout configuration for an enterprise security feel.-----#
st.set_page_config(page_title="Enterprise SOC Dashboard", layout="wide")

st.title("🛡️ Enterprise Security Operations Log Analyzer")
st.markdown("Isolate automated brute-force signatures, filter authentication errors, and audit entry metrics.")

#-----1. Incident Triage Sidebar Section-----#
st.sidebar.header("Incident Triage Filters")
show_brute = st.sidebar.checkbox("🚨 Brute-Force (Invalid/Illegal Users)", value=True)
show_failed = st.sidebar.checkbox("⚠️ Standard Auth Failures", value=True)
show_accepted = st.sidebar.checkbox("✅ Successful Audited Logins", value=True)

#-----File Upload component Section-----#
uploaded_file = st.file_uploader("Upload Server Authentication Log", type=["log", "txt"])

if uploaded_file is not None:
    bytes_data = uploaded_file.getvalue()
    log_lines = bytes_data.decode("utf-8").splitlines()
    
    #We will store records as dictionaries: {'IP': 'xxx', 'Type': 'xxx'}
    parsed_records = []
    ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    
    #-----2. Advanced Multi-Class Security Logic Section-----#
    for line in log_lines:
        log_type = None
        
        #Classify the threat or event vector.
        if "invalid user" in line.lower() or "illegal user" in line.lower():
            if show_brute:
                log_type = "Brute-Force"
        elif "failed" in line.lower():
            if show_failed:
                log_type = "Standard Failure"
        elif "accepted" in line.lower():
            if show_accepted:
                log_type = "Successful Login"

        # If it matches an active filter, extract the source IP address.
        if log_type:
            match = re.search(ip_pattern, line)
            if match:
                parsed_records.append({"IP Address": match.group(1), "Event Type": log_type})

    #-----3. Render Dashboard Analytics if records match criteria Section-----#
    if parsed_records:
        #Convert our raw list of tracking items into a Pandas DataFrame.
        df_raw = pd.DataFrame(parsed_records)
        
        #Calculate distinct metric values for the top row summary blocks.
        total_events = len(df_raw)
        brute_count = len(df_raw[df_raw["Event Type"] == "Brute-Force"])
        failed_count = len(df_raw[df_raw["Event Type"] == "Standard Failure"])
        success_count = len(df_raw[df_raw["Event Type"] == "Successful Login"])

        #Display clean KPI Summary Metrics Boxes.
        m_col1, m_col2, m_col3, m_col4 = st.columns(4)
        m_col1.metric("Total Events Analyzed", total_events)
        m_col2.metric("🚨 Brute-Force", brute_count)
        m_col3.metric("⚠️ Standard Failures", failed_count)
        m_col4.metric("✅ Successful Logins", success_count)
            
        st.write("---")
        
        #Split layout screen: Left for Table data, Right for Multi-Color Visualization.
        col3, col4 = st.columns([1, 1])
        
        with col3:
            st.subheader("📋 Filtered Event Stream Summary")
            #Group data cleanly to show top offending IPs and what type of event they caused.
            df_summary = df_raw.groupby(["IP Address", "Event Type"]).size().reset_index(name="Occurrences")
            df_summary = df_summary.sort_values(by="Occurrences", ascending=False).head(10)
            st.dataframe(df_summary, use_container_width=True, hide_index=True)
            
        with col4:
            st.subheader("📊 Multi-Color Security Matrix Chart")
            
            #Map precise Industry Standard SOC colors to each Event Type.
            color_map = {
                "Brute-Force": "#ff4b4b",       # High Severity Red
                "Standard Failure": "#f1c40f",  # Medium Severity Yellow
                "Successful Login": "#2ebd59"   # Safe Condition Green
            }
            
            #Group for charting, grabbing top 10 unique combinations.
            chart_data = df_raw.groupby(["IP Address", "Event Type"]).size().unstack(fill_value=0)
            active_colors = [color_map[col] for col in chart_data.columns if col in color_map]
            
            #Render stacked horizontal bar chart.
            fig, ax = plt.subplots()
            chart_data.head(10).plot(kind='barh', stacked=True, color=active_colors, ax=ax)
            
            ax.set_xlabel("Number of Occurrences", labelpad=10) # Added spacing below the label
            ax.set_ylabel("Source IP Address")
            
            #Move legend cleanly underneath the 'Number of Occurrences' axis label.
            ax.legend(
                title="Security Event Type", 
                loc='upper center', 
                bbox_to_anchor=(0.5, -0.2), # (X-center, Y-below the chart)
                ncol=3,                     # Displays items side-by-side horizontally
                frameon=True
            )
            
            #Ensure layout handles the extra bottom spacing perfectly.
            plt.tight_layout()
            st.pyplot(fig)
    else:
        st.info("ℹ️ Select triage filters from the sidebar or upload a valid log file to display telemetry data.")
