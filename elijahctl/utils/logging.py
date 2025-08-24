import logging
import sys
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from typing import Optional

console = Console()

def setup_logging(verbose: bool = False, log_file: Optional[Path] = None):
    level = logging.DEBUG if verbose else logging.INFO
    
    handlers = [
        RichHandler(
            console=console,
            show_time=False,
            show_path=False,
            markup=True,
            rich_tracebacks=True
        )
    ]
    
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        handlers.append(file_handler)
    
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=handlers,
        force=True
    )

def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)

def success(message: str):
    console.print(f"[green]✓[/green] {message}")

def error(message: str):
    console.print(f"[red]✗[/red] {message}", style="red")

def warning(message: str):
    console.print(f"[yellow]⚠[/yellow] {message}", style="yellow")

def info(message: str):
    console.print(f"[blue]ℹ[/blue] {message}")

def create_progress():
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    )

def print_table(title: str, data: list, columns: list):
    table = Table(title=title, show_header=True, header_style="bold magenta")
    for col in columns:
        table.add_column(col)
    for row in data:
        table.add_row(*[str(v) for v in row])
    console.print(table)

def print_dict(data: dict, title: Optional[str] = None):
    if title:
        console.print(f"\n[bold]{title}[/bold]")
    for key, value in data.items():
        console.print(f"  {key}: {value}")

def confirm(prompt: str) -> bool:
    response = console.input(f"{prompt} [y/N]: ").strip().lower()
    return response in ['y', 'yes']