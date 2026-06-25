from typing import Dict, Any, List


def build_ioc_index(cases: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Builds a searchable IOC index from every case.
    """

    index = {}

    for case in cases:

        title = case.get("title", "Unknown Case")

        indicators = case.get("indicators", {})

        for category, values in indicators.items():

            if not isinstance(values, list):
                values = [values]

            for value in values:

                key = str(value)

                if key not in index:

                    index[key] = {
                        "type": category,
                        "cases": [],
                        "related": set(),
                    }

                index[key]["cases"].append(title)

                # Everything else inside this case becomes related

                for other_category, other_values in indicators.items():

                    if not isinstance(other_values, list):
                        other_values = [other_values]

                    for other in other_values:

                        if other != value:
                            index[key]["related"].add(str(other))

    return index


def list_iocs(index: Dict[str, Dict[str, Any]]):
    while True:
        print("\n" + "=" * 60)
        print("IOC EXPLORER")
        print("=" * 60)

        iocs = sorted(index)

        for number, ioc in enumerate(iocs, start=1):
            print(f"[{number}] {ioc} ({index[ioc]['type']})")

        print("\n[0] Back")

        choice = input("\nSelect IOC: ").strip()

        if choice == "0":
            return

        if not choice.isdigit():
            print("Invalid selection.")
            continue

        choice = int(choice)

        if 1 <= choice <= len(iocs):
            selected_ioc = iocs[choice - 1]
            show_ioc_details(selected_ioc, index[selected_ioc])
        else:
            print("Invalid selection.")


def show_ioc_details(name: str, data: Dict[str, Any]):
    print("\n" + "=" * 60)
    print("IOC DETAILS")
    print("=" * 60)

    print(f"\nIndicator : {name}")
    print(f"Type      : {data['type']}")

    print("\nCases")
    print("-" * 40)

    for case in sorted(set(data["cases"])):
        print(f"- {case}")

    print("\nRelated Indicators")
    print("-" * 40)

    for related in sorted(data["related"]):
        print(f"- {related}")

    input("\nPress Enter to continue...")