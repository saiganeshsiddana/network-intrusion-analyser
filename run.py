"""
Entry point to launch the Streamlit application.
"""

import os
import sys
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

if __name__ == "__main__":
    os.system("streamlit run app/main.py")
