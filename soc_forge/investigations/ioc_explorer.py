from typing import Dict, Any, List
from soc_forge.ui.colors import Colors
from soc_forge.ui.panels import header, info_panel, menu_option, warning, footer
from soc_forge.ui.screen import begin_screen


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

def list_iocs(index: Dict[str, Dict[str, Any]], title: str = "IOC EXPLORER"):
    while True:
        header(title)

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
            show_ioc_details(selected_ioc, index[selected_ioc], index)
        else:
            print("Invalid selection.")


def show_ioc_details(name: str, data: Dict[str, Any], index: Dict[str, Dict[str, Any]], clear_screen=None):
    if clear_screen:
        clear_screen()
    while True:
        begin_screen("ENTITY DETAILS")

        info_panel(
            "ENTITY DETAILS",
            [
                ("Indicator", name),
                ("Type", data["type"]),
                ("Cases", len(data["cases"])),
                ("Related", len(data["related"])),
            ],
        )

        print("\nCases")
        print("-" * 40)

        for case in sorted(set(data["cases"])):
            print(f"- {case}")

        print("\nRelated Indicators")
        print("-" * 40)

        for related in sorted(data["related"]):
            print(f"- {related}")

            print()
            menu_option("1", "Relationship Graph")
            menu_option("2", "Pivot to Related Entity")
            menu_option("0", "Back")
            footer()

            choice = input("\nSelect option: ").strip()

            if choice == "1":
                show_relationship_graph(name, data, clear_screen)
            elif choice == "2":
                pivot_to_related_entity(name, data, index, clear_screen)
            elif choice == "0":
                return
            else:
                print("Invalid option.")

def pivot_to_related_entity(
    name: str,
    data: Dict[str, Any],
    index: Dict[str, Dict[str, Any]],
    clear_screen=None,
):
    if clear_screen:
        clear_screen()
    related = sorted(data.get("related", []))

    if not related:
        warning("No related entities available.")
        input("\nPress Enter to return...")
        return

    begin_screen("PIVOT TO RELATED ENTITY")

    print(f"\nCurrent Entity: {name}\n")

    for number, entity in enumerate(related, start=1):
        print(f"[{number}] {entity}")

    print("[0] Back")

    choice = input("\nSelect entity: ").strip()

    if choice == "0":
        return

    if not choice.isdigit():
        print("Invalid selection.")
        input("\nPress Enter to return...")
        return

    choice_num = int(choice)

    if not (1 <= choice_num <= len(related)):
        print("Invalid selection.")
        input("\nPress Enter to return...")
        return

    selected_entity = related[choice_num - 1]

    if selected_entity not in index:
        warning("Selected entity is not indexed yet.")
        input("\nPress Enter to return...")
        return

    show_ioc_details(selected_entity, index[selected_entity], index)

def show_relationship_graph(name: str, data: Dict[str, Any], clear_screen=None):
    if clear_screen:
        clear_screen()
    while True:
        related = sorted(data.get("related", []))
        cases = sorted(set(data.get("cases", [])))

        begin_screen("ENTITY RELATIONSHIP GRAPH")

        print(f"\n{Colors.BOLD}{name}{Colors.RESET}")

        if related:
            print(Colors.GRAY + "│" + Colors.RESET)
            for idx, item in enumerate(related):
                connector = "├──" if idx < len(related) - 1 else "└──"
                print(f"{Colors.GRAY}{connector}{Colors.RESET} {item}")

        if cases:
            print(Colors.GRAY + "│" + Colors.RESET)
            print(Colors.GRAY + "└── Cases" + Colors.RESET)
            for case in cases:
                print(f"    {Colors.GRAY}└──{Colors.RESET} {case}")

        print()
        menu_option("0", "Back")

        choice = input("\nSelect option: ").strip()

        if choice == "0":
            return
        else:
            print("Invalid option.")