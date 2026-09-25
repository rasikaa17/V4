"""
app.py
-------
Main Flask application entry point.

PHASE 1 SCOPE ONLY:
This currently just proves the Flask app starts correctly and serves
a homepage. In later phases we will:
  - Phase 7: connect the SQLite database
  - Phase 8: register the routes/threats.py and routes/analysis.py blueprints
  - Phase 9-10: build out the real dashboard and analysis pages

Run with:
    python app.py
"""

from flask import Flask, render_template

from config import Config


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    @app.route("/")
    def home():
        return render_template("index.html")

    @app.route("/health")
    def health():
        """Simple health-check endpoint to confirm the server is alive.
        Useful for quickly testing the app without opening a browser."""
        return {"status": "ok", "message": "Threat Intelligence Platform is running"}

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
