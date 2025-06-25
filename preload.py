import sys
from pathlib import Path

p = str(Path(__file__).resolve().parent / 'script')
if p not in sys.path:
    sys.path.insert(0, p)

def preload(parser):
    parser.add_argument("--encrypt-pass", type=str, help="The password to enable image encryption.", default=None)