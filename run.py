import os
from app import create_app

app = create_app()

if __name__ == "__main__":
    # Debug is OFF unless FLASK_DEBUG is explicitly enabled in .env.
    # Never run with debug=True in production — the Werkzeug debugger
    # allows arbitrary code execution.
    debug = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true", "yes", "on")
    app.run(debug=debug)
