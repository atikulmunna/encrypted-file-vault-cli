"""Typer application bootstrap for VaultCLI."""

from __future__ import annotations

from typing import Annotated

import typer

from vaultcli import __version__
from vaultcli.cli import output
from vaultcli.cli.commands import add, create, extract, hidden, info, list_cmd, rekey, verify, wipe
from vaultcli.cli.state import AppState

app = typer.Typer(
    help="Security-focused CLI for encrypted file vaults.",
    no_args_is_help=True,
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        output.emit({"vaultcli_version": __version__}, json_mode=False)
        raise typer.Exit()


@app.callback()
def main_callback(
    ctx: typer.Context,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose output."),
    ] = False,
    json_mode: Annotated[
        bool,
        typer.Option("--json", help="Emit structured JSON output."),
    ] = False,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Show the VaultCLI version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Initialize application state for subcommands."""
    del version
    state = AppState()
    state.verbose = verbose
    state.json = json_mode
    ctx.obj = state


app.command("create")(create.create_command)
app.command("add")(add.add_command)
app.command("extract")(extract.extract_command)
app.command("list")(list_cmd.list_command)
app.command("verify")(verify.verify_command)
app.command("rekey")(rekey.rekey_command)
app.command("info")(info.info_command)
app.command("wipe")(wipe.wipe_command)
app.add_typer(hidden.app, name="hidden")


def main() -> None:
    """Run the Typer CLI application."""
    app()
