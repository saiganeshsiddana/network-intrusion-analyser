"""
Entry point to launch the Streamlit application.
"""

import subprocess
import sys
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

if __name__ == "__main__":
    # Use subprocess instead of os.system for better portability
    subprocess.run([sys.executable, "-m", "streamlit", "run", "app/main.py"])
