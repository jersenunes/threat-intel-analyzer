import sys
from configs.settings import *
from enrichment.orchestrator import orchestrator


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py json=examples/inputs_file.json" \
        "Usage: python main.py ip=1.1.1.1" \
        "Usage: python main.py domain=google.com" \
        "Usage: python main.py url=https://www.youtube.com" \
        "Usage: python main.py hash=23792BDD1136C3A69AD6A5BDC0914A45" \
        "Usage: python main.py file=examples/file.pdf")
        sys.exit(1)

    input_arg = sys.argv[1]

    orchestrator(input=input_arg)

if __name__ == "__main__":
    main()
