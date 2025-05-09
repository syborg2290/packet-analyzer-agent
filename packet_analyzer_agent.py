import subprocess
import sqlite3
import signal
import sys
import time
import threading
from datetime import datetime
from langchain_ollama import OllamaLLM
from langchain.prompts import PromptTemplate

# SQLite setup
DB_PATH = "packet_queue.db"


def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                raw_data TEXT,
                status TEXT DEFAULT 'pending',
                analysis TEXT
            )
        """
        )
        conn.commit()
        conn.close()
    except sqlite3.DatabaseError as e:
        print(f"⚠️ Database error during DB initialization: {e}")
    except Exception as e:
        print(f"⚠️ Unexpected error during DB initialization: {e}")


def insert_packet(timestamp, raw_data):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO packets (timestamp, raw_data) VALUES (?, ?)",
            (timestamp, raw_data),
        )
        conn.commit()
        conn.close()
    except sqlite3.DatabaseError as e:
        print(f"⚠️ Database error while inserting packet: {e}")
    except Exception as e:
        print(f"⚠️ Unexpected error while inserting packet: {e}")


def get_next_pending_packet():
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, raw_data FROM packets WHERE status = 'pending' ORDER BY id ASC LIMIT 1"
        )
        result = cursor.fetchone()
        if result:
            # Mark as 'processing' immediately
            cursor.execute(
                "UPDATE packets SET status = 'processing' WHERE id = ?", (result[0],)
            )
            conn.commit()
        conn.close()
        return result
    except sqlite3.DatabaseError as e:
        print(f"⚠️ Database error while fetching next pending packet: {e}")
    except Exception as e:
        print(f"⚠️ Unexpected error while fetching next pending packet: {e}")
    return None


def mark_packet_processed(packet_id, analysis):
    try:
        print(f"📦 Marking packet #{packet_id} as processed with analysis: {analysis}")

        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        cursor = conn.cursor()

        # Log the SQL query and parameters to check what is being executed
        query = "UPDATE packets SET status = 'done', analysis = ? WHERE id = ?"
        print(f"Executing SQL: {query}, Params: {(analysis, packet_id)}")

        cursor.execute(query, (analysis, packet_id))
        conn.commit()

        # Confirm successful update
        if cursor.rowcount == 0:
            print(
                f"⚠️ No rows updated for packet #{packet_id}. It might have already been processed."
            )
        else:
            print(f"✅ Successfully marked packet #{packet_id} as processed.")

        conn.close()

    except sqlite3.DatabaseError as e:
        print(f"⚠️ Database error while marking packet #{packet_id} processed: {e}")
    except Exception as e:
        print(f"⚠️ Unexpected error while marking packet #{packet_id} processed: {e}")


# Signal handler
def signal_handler(sig, frame):
    try:
        print("\n🛑 Exiting packet analyzer...")
        sys.exit(0)
    except Exception as e:
        print(f"⚠️ Error in signal handler: {e}")


signal.signal(signal.SIGINT, signal_handler)

# LangChain setup
try:
    llm = OllamaLLM(model="llama3.1")
    prompt_template = PromptTemplate(
        input_variables=["packet_data"],
        template="""
    You are a cybersecurity AI agent specialized in network threat analysis.

    Analyze the following network packet data. Determine if it contains any signs of abnormal behavior or critical security issues. Based on your analysis, classify the packet as one of the following:
    - **benign** — standard behavior, no indication of threat
    - **suspicious** — potentially harmful, but not conclusively malicious
    - **malicious** — clear signs of attack, threat, or exploit attempt

    In your analysis, look for attributes such as:
    - Unusual port usage or protocol violations
    - Packet flooding or DoS patterns
    - Spoofed IP addresses or malformed headers
    - Evidence of data exfiltration, command and control (C2) behavior, or malware delivery
    - Indicators of privilege escalation or lateral movement

    After classification, provide a brief explanation (1-2 sentences) citing specific packet characteristics that led to your conclusion.

    Packet Data:
    ---------------------
    {packet_data}
    ---------------------
    Classification and Explanation:""",
    )
    chain = prompt_template | llm
except Exception as e:
    print(f"⚠️ Error setting up LangChain: {e}")


# Packet capture
def stream_packets():
    try:
        cmd = ["sudo", "ngrep", "-d", "any", "-t", ".*"]
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        for line in process.stdout:
            yield line.strip()
    except subprocess.SubprocessError as e:
        print(f"⚠️ Error while capturing packets: {e}")
    except Exception as e:
        print(f"⚠️ Unexpected error while capturing packets: {e}")


# Insert captured packets into DB
def packet_capturer():
    try:
        print("📡 Capturing ALL packets...")
        current_packet = []
        timestamp = None

        for line in stream_packets():
            if line.startswith("T "):  # new packet begins
                if current_packet:
                    raw_data = "\n".join(current_packet)
                    insert_packet(timestamp or datetime.now().isoformat(), raw_data)
                    current_packet = [line]
                    timestamp = (
                        line.split("T ")[1]
                        if "T " in line
                        else datetime.now().isoformat()
                    )
                else:
                    current_packet.append(line)
                    timestamp = (
                        line.split("T ")[1]
                        if "T " in line
                        else datetime.now().isoformat()
                    )
            else:
                current_packet.append(line)
    except Exception as e:
        print(f"⚠️ Unexpected error during packet capturing: {e}")


# Analyze pending packets
def packet_analyzer():
    try:
        print("🧠 Starting LLM packet analyzer...")
        while True:
            row = get_next_pending_packet()
            if row:
                packet_id, raw_data = row
                try:
                    result = chain.invoke({"packet_data": raw_data})
                    mark_packet_processed(packet_id, result)
                    print(f"\n✅ Analyzed packet #{packet_id}:\n{result}")
                except Exception as e:
                    print(f"⚠️ Error analyzing packet #{packet_id}: {e}")
            else:
                time.sleep(0.5)  # avoid tight loop
    except Exception as e:
        print(f"⚠️ Unexpected error in packet analysis loop: {e}")


# Main
if __name__ == "__main__":
    try:
        init_db()
        threading.Thread(target=packet_capturer, daemon=True).start()
        packet_analyzer()
    except Exception as e:
        print(f"⚠️ Error in main execution: {e}")
