"""FastAPI server: exposes the simulation as JSON and serves the dashboard."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ppm_traceback.experiments import sweep
from ppm_traceback.simulation import TraceConfig, run_trace

WEB_DIR = Path(__file__).resolve().parent.parent / "web"

app = FastAPI(title="TraceBack", description="IP traceback with probabilistic packet marking")


class TraceRequest(BaseModel):
    scheme: Literal["node", "edge"] = "node"
    p: float = Field(0.04, gt=0, lt=1)
    path_length: int = Field(15, ge=3, le=25)
    attackers: int = Field(1, ge=1, le=6)
    packets: int = Field(100_000, ge=100, le=200_000)
    forge: bool = False
    seed: int | None = Field(7, ge=0, le=1_000_000)


@app.post("/api/trace")
def trace(req: TraceRequest) -> dict:
    return run_trace(TraceConfig(**req.model_dump()))


@app.get("/api/experiments")
def experiments(
    variable: Literal["p", "d"] = "p",
    fixed: float = Query(None),
    trials: int = Query(20, ge=5, le=60),
) -> dict:
    if fixed is None:
        fixed = 15 if variable == "p" else 0.04
    if variable == "p" and not 3 <= fixed <= 25:
        raise HTTPException(422, "path length must be between 3 and 25")
    if variable == "d" and not 0 < fixed < 1:
        raise HTTPException(422, "p must be between 0 and 1")
    return sweep(variable, float(fixed), trials)


class NoCacheStaticFiles(StaticFiles):
    """Always revalidate, so edits to the dashboard show up on reload."""

    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"
        return response


app.mount("/", NoCacheStaticFiles(directory=WEB_DIR, html=True), name="web")
