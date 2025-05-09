import streamlit as st
import sqlite3
import time
from datetime import datetime

DB_PATH = "packet_queue.db"

# Connect to DB
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    return conn

# Get packets with pagination
def get_packets(page, status_filter=None, date_filter=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Base query for packets
    query = "SELECT * FROM packets WHERE 1=1"
    
    # Apply filters
    if status_filter:
        query += " AND status = ?"
    if date_filter:
        query += " AND timestamp LIKE ?"
    
    query += " ORDER BY timestamp DESC LIMIT 10 OFFSET ?"
    
    params = []
    if status_filter:
        params.append(status_filter)
    if date_filter:
        params.append(f"%{date_filter}%")
    params.append(page * 10)  # OFFSET for pagination
    
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()
    
    return rows

# Display packet analysis
def display_packet_analysis(packet_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT analysis FROM packets WHERE id = ?", (packet_id,))
    analysis = cursor.fetchone()
    conn.close()
    
    if analysis:
        return analysis[0]
    return "No analysis available yet."

# Streamlit UI
def display_packet_table(page, status_filter, date_filter):
    packets = get_packets(page, status_filter, date_filter)
    
    if packets:
        for packet in packets:
            packet_id, timestamp, raw_data, status, analysis = packet
            st.write(f"**Packet ID**: {packet_id} | **Timestamp**: {timestamp} | **Status**: {status}")
            st.text_area("Raw Data", raw_data, height=100)
            
            if status == "done":
                st.subheader("Analysis")
                st.write(analysis)
            else:
                st.warning("Analysis not yet available.")
            
            st.markdown("---")
    else:
        st.write("No packets found for the given filters.")

# Live packet display
def display_live_packets():
    # This would be the function to stream live packet data if needed
    st.subheader("Live Packet Stream")
    while True:
        packet_data = capture_packet_data()  # This should connect to the real-time capture function
        st.write(packet_data)
        time.sleep(1)

# UI components for filters and pagination
def packet_page_ui():
    st.title("Network Packet Analysis")

    status_filter = st.selectbox("Filter by status", ["All", "pending", "processing", "done"])
    status_filter = None if status_filter == "All" else status_filter

    date_filter = st.text_input("Filter by date (YYYY-MM-DD)", "")
    
    page = st.number_input("Page", min_value=0, max_value=100, step=1, value=0)

    if st.button("Show Packets"):
        display_packet_table(page, status_filter, date_filter)

    if st.button("Show Live Packets"):
        display_live_packets()

# Main function to run the Streamlit app
if __name__ == "__main__":
    packet_page_ui()

