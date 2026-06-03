---
slug: cisco-meraki-soc-dashboard
title: "Building a Cross-Platform Security Log Visualizer with Python and Streamlit"
description: "Learn how to build a unified local security dashboard using Python and Pandas to ingest, normalize, and visualize fragmented network firewall and endpoint log formats."
authors: Nuwan Kulasuriya	
contributors: --
published: 2026-06-03
keywords: ['security-monitoring', 'streamlit', 'cisco-meraki', 'log-analysis', 'python']
license: '[CC BY-ND 4.0](https://creativecommons.org/licenses/by-nd/4.0)'
---

## Introduction

In an enterprise IT infrastructure, security administrators often navigate fragmented monitoring tools—checking a Linux syslog view, monitoring a Windows Active Directory controller, and hunting through edge network appliances. 

This guide demonstrates how to build a unified, local Security Operations Center (SOC) visualization application using Python, Pandas, and Streamlit. This utility ingest raw strings and structured CSV sheets, normalizes varying vendor terminologies, and displays threat matrices in real-time.

## Before You Begin

1. If you do not already have a virtual machine to run the workspace, create a Compute Instance with at least 4 GB of memory running Ubuntu 24.04 LTS. See our [Creating a Compute Instance](/docs/products/compute/compute-instances/guides/create/) guide.
1. Follow our [Setting Up and Securing a Compute Instance](/docs/products/compute/compute-instances/guides/set-up-and-secure/) guide to update your package registries and configure a limited user account.
1. Ensure your local machine has Python 3.10 or higher installed alongside the PIP package manager.

{{< note >}}
This guide is written for a non-root user. Commands that require elevated terminal privileges are explicitly prefixed with `sudo`.
{{< /note >}}

## Install Core Project Dependencies

1. Initialize your project directory and create a Python virtual environment to cleanly isolate your data science libraries:
```command
mkdir ~/security_dashboard && cd ~/security_dashboard
python3 -m venv venv
source venv/bin/activate


Install the required external libraries using the Python package manager:

Code snippet

pip install streamlit pandas matplotlib

Configure Page Architecture and Enterprise Header

    Create a script named app.py inside your working directory using your preferred text editor.

    Populate the top section of the script to establish wide-layout rendering properties and structure the main introductory callout block:

Python

import streamlit as st
import pandas as pd
import re
import matplotlib.pyplot as plt

st.set_page_config(page_title="Universal Security Log Analyzer", layout="wide")
st.title("🛡️ Universal Enterprise Security Log Visualizer")

st.markdown("""
### Multi-Platform SIEM & Triage Utility
This analytical application provides a unified interface to parse, categorize, and visualize security logs.
* **Linux Streams:** Ingests core authentication strings (`/var/log/auth.log`).
* **Network Firewalls:** Processes appliance events (e.g., **Cisco Meraki MX** connection drops).
* **Windows Security Logs:** Audits Active Directory endpoint trails (**Event IDs 4625/4624**).
""")
st.write("---")

Construct the Interactive Sidebar Filter Module

    Append the configuration sidebar code to build operational control variables. This segment reads custom brand icons into the UI safely:

Python

st.sidebar.header("Log Source Configuration")
log_format = st.sidebar.selectbox("Log File Format", ["Standard Text Log (Linux/Syslog)", "Enterprise CSV Export (Meraki/Windows/Firewall)"])

st.sidebar.write("---")
st.sidebar.header("Incident Triage Filters")

try:
    st.sidebar.image("Bug-Folder--Streamline-Freehand.png", width=40)
except Exception:
    pass

show_brute = st.sidebar.checkbox("Brute-Force / Account Probing", value=True)
show_failed = st.sidebar.checkbox("⚠️ Authentication Failures / Drops", value=True)
show_accepted = st.sidebar.checkbox("✅ Successful Audited Access", value=True)

Build the Heuristic Parsing Router

    Add the file uploading component and the foundational string-cleansing loops to ingest CSV files and extract baseline IPv4 targets:

Python

uploaded_file = st.file_uploader("Upload Security Log File", type=["log", "txt", "csv"])

if uploaded_file is not None:
    parsed_records = []
    ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

    if log_format == "Enterprise CSV Export (Meraki/Windows/Firewall)":
        csv_df = pd.read_csv(uploaded_file)
        csv_df.columns = [col.strip() for col in csv_df.columns]
        
        for index, row in csv_df.iterrows():
            line = str(row.get("Details", row.get("Message", ""))).lower()
            log_type = None
            
            if "invalid user" in line or "illegal user" in line or "brute" in line:
                if show_brute: log_type = "Brute-Force"
            elif "failed" in line or "deny" in line or "block" in line or "failure" in line:
                if show_failed: log_type = "Standard Failure"
            elif "accepted" in line or "allow" in line or "success" in line:
                if show_accepted: log_type = "Successful Login"

Calculate Metric Summary Banners

    Calculate categorical sums from your sanitized rows and format horizontal metric banners across the top viewport:

Python

            if log_type:
                ip_match = re.search(ip_pattern, line)
                ip_address = ip_match.group(1) if ip_match else "Unknown IP"
                parsed_records.append({"IP Address": ip_address, "Event Type": log_type})

    if parsed_records:
        df_raw = pd.DataFrame(parsed_records)
        
        m_col1, m_col2, m_col3 = st.columns(3)
        m_col1.metric("Total Events Analyzed", len(df_raw))
        m_col2.metric("💥 Brute-Force Alerts", len(df_raw[df_raw["Event Type"] == "Brute-Force"]))
        m_col3.metric("⚠️ Access Denied / Drops", len(df_raw[df_raw["Event Type"] == "Standard Failure"]))

Render the Stacked Severity Matrix Chart

    Split the remaining screen layout into balanced columns. The left column displays an aggregated tracking leaderboard, while the right uses a custom hexadecimal layout map to generate an intuitive multi-color chart:

Python

        col3, col4 = st.columns([1, 1])
        with col3:
            st.subheader("📋 Filtered Event Stream Summary")
            df_summary = df_raw.groupby(["IP Address", "Event Type"]).size().reset_index(name="Occurrences")
            st.dataframe(df_summary, use_container_width=True, hide_index=True)
            
        with col4:
            st.subheader("📊 Multi-Color Security Matrix Chart")
            color_map = {"Brute-Force": "#ff4b4b", "Standard Failure": "#f1c40f", "Successful Login": "#2ebd59"}
            chart_data = df_raw.groupby(["IP Address", "Event Type"]).size().unstack(fill_value=0)
            active_colors = [color_map[col] for col in chart_data.columns if col in color_map]
            
            fig, ax = plt.subplots()
            chart_data.head(10).plot(kind='barh', stacked=True, color=active_colors, ax=ax)
            ax.set_xlabel("Number of Occurrences")
            ax.legend(title="Event Type", loc='upper center', bbox_to_anchor=(0.5, -0.2), ncol=3)
            st.pyplot(fig)

Run and Verify the Application

    Save your script edits, open your terminal window, and initiate your Streamlit background microservice host:

Code snippet

streamlit run app.py


Access the provided local loopback URL inside your browser environment (http://localhost:8501) to test your universal normalization controls.
