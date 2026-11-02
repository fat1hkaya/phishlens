"""Minimal Flask UI: upload an .eml, get an interactive report."""

from __future__ import annotations

import os
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, abort, redirect, render_template, request, url_for

from phishlens import __version__
from phishlens.analyzer import analyze_bytes
from phishlens.intel import IntelClient
from phishlens.models import AnalysisResult
from phishlens.report import MITRE_NAMES, RECOMMENDATIONS, to_json, to_markdown

MAX_MB = int(os.getenv("PHISHLENS_MAX_MB", "10"))
SAMPLES_DIR = Path(os.getenv("PHISHLENS_SAMPLES", Path(__file__).resolve().parents[2] / "samples"))
CACHE_SIZE = 50


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_MB * 1024 * 1024
    results: OrderedDict[str, AnalysisResult] = OrderedDict()

    def remember(result: AnalysisResult) -> str:
        rid = uuid.uuid4().hex
        results[rid] = result
        while len(results) > CACHE_SIZE:
            results.popitem(last=False)
        return rid

    def sample_names() -> list[str]:
        return sorted(p.name for p in SAMPLES_DIR.glob("*.eml")) if SAMPLES_DIR.is_dir() else []

    @app.context_processor
    def inject_version():
        return {"version": __version__}

    @app.get("/")
    def index(error: str | None = None):
        intel = IntelClient()
        providers = {"VirusTotal": bool(intel.vt_key), "AbuseIPDB": bool(intel.abuse_key),
                     "URLhaus": bool(intel.urlhaus_key)}
        return render_template("index.html", samples=sample_names(), providers=providers,
                               max_mb=MAX_MB, error=error)

    @app.post("/analyze")
    def analyze():
        upload = request.files.get("eml")
        if not upload or not upload.filename:
            return index(error="Please choose an .eml file.")
        data = upload.read()
        if not data.strip():
            return index(error="The uploaded file is empty.")
        result = analyze_bytes(data, Path(upload.filename).name, IntelClient())
        return redirect(url_for("report", rid=remember(result)))

    @app.get("/sample/<name>")
    def sample(name: str):
        if name not in sample_names():
            abort(404)
        result = analyze_bytes((SAMPLES_DIR / name).read_bytes(), name, IntelClient())
        return redirect(url_for("report", rid=remember(result)))

    @app.get("/report/<rid>")
    def report(rid: str):
        result = results.get(rid) or abort(404)
        return render_template("report.html", r=result, rid=rid, standalone=False,
                               mitre_names=MITRE_NAMES, recommendations=RECOMMENDATIONS[result.verdict],
                               generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))

    @app.get("/report/<rid>.<fmt>")
    def download(rid: str, fmt: str):
        result = results.get(rid) or abort(404)
        if fmt == "json":
            return Response(to_json(result), mimetype="application/json",
                            headers={"Content-Disposition": f"attachment; filename={rid}.json"})
        if fmt == "md":
            return Response(to_markdown(result), mimetype="text/markdown",
                            headers={"Content-Disposition": f"attachment; filename={rid}.md"})
        abort(404)

    @app.post("/api/analyze")
    def api_analyze():
        """JSON API - e.g. for a SOAR (Shuffle) workflow: curl -F eml=@mail.eml host/api/analyze"""
        upload = request.files.get("eml") if request.mimetype == "multipart/form-data" else None
        # parse_form_data=False keeps form-encoded raw bodies (curl --data-binary) intact.
        data = upload.read() if upload else request.get_data(parse_form_data=False)
        if not data:
            return {"error": "send the .eml as multipart field 'eml' or as raw body"}, 400
        name = Path(upload.filename).name if upload and upload.filename else "message.eml"
        result = analyze_bytes(data, name, IntelClient())
        return Response(to_json(result), mimetype="application/json")

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "version": __version__}

    return app


def main() -> None:
    host = os.getenv("PHISHLENS_HOST", "127.0.0.1")
    port = int(os.getenv("PHISHLENS_PORT", "5000"))
    create_app().run(host=host, port=port)


if __name__ == "__main__":
    main()
