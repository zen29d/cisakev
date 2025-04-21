import argparse
import os
import sys
import json
import csv
from rich.console import Console

# cisa_kev* modules
from cisa_kev import download_catalog 
from cisa_kev_query import query_kevs, pretty_print_kevs, convert_wildcard, convert_year
from cisa_kev_watcher import check_new_kev
import cisa_kev_db as kev_db 
from Base import SQLITE_DB 
from logger import init_logger 

log = init_logger()
console = Console()

def show_help():
    console.print(
        """
[bold cyan]CISA KEV CLI Tool[/bold cyan] - [dim]Query and Manage Known Exploited Vulnerabilities (KEVs)[/dim]

[bold]USAGE[/bold]
  cisakev db [--download | --update]
  cisakev list [options]
  cisakev export [options] --output FILE [--format FORMAT]

[bold]COMMANDS[/bold]
  [green]db[/green]           Manage the local KEV database.
                  [blue]--download[/blue]     Download KEV catalog and create the database.
                  [blue]--update[/blue]       Refresh the local KEV database and display newly added KEVs.

  [green]list[/green]         List filtered KEVs from the local database.
                  [blue]--cve[/blue] <TEXT>     Filter by CVE ID (supports wildcard: e.g. CVE-2023, 2024-30088)
                  [blue]--vendor[/blue] <TEXT>  Filter by vendor/project name.
                  [blue]--year[/blue] <TEXT>    Filter by year range: 2024, 2023-, 2022+, 2021-2022
                  [blue]--limit[/blue] <INTEGER | all>  Max number of results (use 'all' to show everything). Default: 5

  [green]export[/green]       Export filtered KEVs to a file.
                  [blue]--cve[/blue] <TEXT>     Filter by CVE ID (supports wildcard: e.g. CVE-2023, 2024-30088)
                  [blue]--vendor[/blue] <TEXT>  Filter by vendor/project name.
                  [blue]--year[/blue] <TEXT>    Filter by year range: 2024, 2023-, 2022+, 2021-2022
                  [blue]--limit[/blue] <INTEGER | all>  Max number of results (use 'all' for no limit). Default: 50
                  [blue]--output[/blue] <PATH>    Output file path (e.g. results.json or results.csv). [required]
                  [blue]--format[/blue] <csv | json> Output format. Default: csv

[bold]EXAMPLES[/bold]
  cisakev db --download
  cisakev db --update
  cisakev list --vendor microsoft --year 2023+ --limit 10
  cisakev export --cve CVE-2025 --output export.csv  --format csv --limit all
"""
    )


def handle_list(args):
    if not os.path.exists(SQLITE_DB):
        if not prompt_download():
            return
    try:
        limit = None if args.limit == "all" else int(args.limit)
        cve_id = convert_wildcard(args.cve)
        date_from, date_to = convert_year(args.year)

        kevs = query_kevs(
            SQLITE_DB,
            cve_id=cve_id,
            vendor=args.vendor,
            since_date=date_from,
            until_date=date_to,
            limit=limit,
        )
        pretty_print_kevs(kevs)
    except ValueError:
        console.print("[red]Invalid limit value.  Must be an integer or 'all'.[/red]")
        sys.exit(1)
    except Exception as E:
        console.print(f"[red]An unexpected error occurred: {E}[/red]")
        sys.exit(1)


def handle_export(args):
    if not os.path.exists(SQLITE_DB):
        if not prompt_download():
            return

    try:
        limit = None if args.limit == "all" else int(args.limit)
        cve_id = convert_wildcard(args.cve)
        date_from, date_to = convert_year(args.year)

        kevs = query_kevs(
            SQLITE_DB,
            cve_id=cve_id,
            vendor=args.vendor,
            since_date=date_from,
            until_date=date_to,
            limit=limit,
        )

        if not kevs:
            console.print("[yellow]No data to export based on the provided filters[/yellow]")
            return

        with open(args.output, "w", encoding="utf-8") as f:
            if args.format == "json":
                json.dump(kevs, f, indent=2)
            elif args.format == "csv":
                if kevs:
                    writer = csv.DictWriter(f, fieldnames=kevs[0].keys())
                    writer.writeheader()
                    writer.writerows(kevs)
                else:
                    console.print("[yellow]No data to write to CSV file[/yellow]")
            else:
                console.print(f"[red]Unsupported export format: {args.format}[/red]")
                sys.exit(1)
        console.print(f"[green]Successfully exported {len(kevs)} KEVs to '{args.output}' in {args.format} format[/green]")
    except ValueError:
        console.print("[red]Invalid limit value. Must be an integer or 'all'.[/red]")
        sys.exit(1)
    except Exception as E:
        console.print(f"[red]An unexpected error occurred: {E}[/red]")
        sys.exit(1)


def prompt_download():
    choice = input("Database not found. Download now? (y/N): ").strip().lower()
    if choice == "y":
        try:
            console.print("[blue]Downloading the CISA KEV catalog...[/blue]")
            download_catalog()
            console.print("[green]Successfully downloaded the CISA KEV catalog and created the database[/green]")
            return True
        except Exception as E:
            console.print(f"[red]Error during download: {E}[/red]")
            return False
    else:
        console.print("[yellow]Exiting...[/yellow]")
        return False


def handle_db(args):
    if args.download:
        download_catalog()
        return

    # Exit if user declines download
    if not os.path.exists(SQLITE_DB):
        if not prompt_download():
            sys.exit(1) 
            return

    if args.update:
        try:
            console.print("[blue]Updating the CISA KEV database...[/blue]")
            existing_cves = set(kev["cveID"] for kev in query_kevs(SQLITE_DB, limit=None))
            download_catalog()
            updated_cves = set(kev["cveID"] for kev in query_kevs(SQLITE_DB, limit=None))
            new_entries = updated_cves - existing_cves
            if new_entries:
                console.print(f"[green]Found {len(new_entries)} new KEVs[/green]")
                new_kevs = [kev for kev in query_kevs(SQLITE_DB, limit=None) if kev["cveID"] in new_entries]
                pretty_print_kevs(new_kevs)
            else:
                console.print("[cyan]Database is already up-to-date[/cyan]")
        except Exception as E:
            console.print(f"[red]An unexpected error occurred during update: {E}[/red]")
            sys.exit(1)
    else:
        props = kev_db.load_properties_from_db(SQLITE_DB)
        if props:
            console.print(f"[bold]Database Version:[/bold] {props['catalogVersion']}")
            console.print(f"[bold]Last Published:[/bold] {props['dateReleased']}")
            console.print(f"[bold]Total KEVs:[/bold] {props['count']}")
        else:
            console.print("[yellow]Could not retrieve database properties[/yellow]")


def main():
    if len(sys.argv) == 1:
        show_help()
        sys.exit(0)

    parser = argparse.ArgumentParser(
        description="CISA KEV CLI Tool", 
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # db
    p_db = subparsers.add_parser("db", help="Manage the local KEV database")
    p_db.add_argument("--download", action="store_true", help="Download KEV catalog")
    p_db.add_argument("--update", action="store_true", help="Update KEV catalog and show newly added entries")
    p_db.set_defaults(func=handle_db)

    # list
    p_list = subparsers.add_parser("list", help="List KEVs from local database")
    p_list.add_argument("--cve", type=str, help="Filter by CVE ID (wildcard supported)")
    p_list.add_argument("--vendor", type=str, help="Filter by vendor/project")
    p_list.add_argument("--year", type=str, help="Filter by year (e.g. 2025, 2024-, 2023+, 2024-2025)")
    p_list.add_argument("--limit", type=str, default="5", help="Limit number of results (or 'all')")
    p_list.set_defaults(func=handle_list)

    # export
    p_export = subparsers.add_parser("export", help="Export filtered KEVs to a file")
    p_export.add_argument("--cve", type=str, help="Filter by CVE ID (wildcard supported)")
    p_export.add_argument("--vendor", type=str, help="Filter by vendor/project")
    p_export.add_argument("--year", type=str, help="Filter by year (e.g. 2025, 2024-, 2023+, 2024-2025)")
    p_export.add_argument("--limit", type=str, default="50", help="Limit number of results (or 'all')")
    p_export.add_argument("--output", type=str, required=True, help="Output file (e.g., output.json or .csv)")
    p_export.add_argument("--format", type=str, default="csv", choices=["json", "csv"], help="Output format")
    p_export.set_defaults(func=handle_export)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
