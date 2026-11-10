import importlib, traceback, sys
importlib.invalidate_caches()
try:
    m = importlib.import_module("thebetterCA_1")
    print("import OK")
    print("module file:", getattr(m, "__file__", None))
    print("'summarize' in module:", "summarize" in dir(m))
    print("summarize obj:", repr(getattr(m, "summarize", None)))
    app = getattr(m, "app", None)
    print("app type:", type(app))
    # Try common Typer internals
    try:
        print("app.commands keys:", list(getattr(app, "commands", {}).keys()))
    except Exception as e:
        print("error getting app.commands:", e)
    try:
        # Typer uses click — list registered callback names if available
        cmds = getattr(app, "registered_commands", None)
        print("app.registered_commands:", cmds)
    except Exception as e:
        print("error getting app.registered_commands:", e)
except Exception:
    traceback.print_exc()
    sys.exit(1)
    """Summarize failed SSH login attempts from auth.log files."""