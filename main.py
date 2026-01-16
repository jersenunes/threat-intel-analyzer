import sys
from configs.settings import *
from enrichment.orchestrator import orchestrator


def main():
    if len(sys.argv) < 2:
        print(USAGE_MESSAGE)
        sys.exit(1)

    orchestrator(input=sys.argv)

if __name__ == "__main__":
    main()
