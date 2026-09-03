"""
AI Capability Demo — Plotly Chart Renderers
Dark theme, transparent backgrounds, Inter font, design-system colours.
AGENTS.md Section 20.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

import plotly.graph_objects as go

from app.ui.theme import (
    ACCENT_BLUE,
    ACCENT_GREEN,
    ACCENT_PURPLE,
    ACCENT_RED,
    BG_GLASS,
    BORDER_GLASS,
    RAG_AMBER,
    RAG_GREEN,
    RAG_RED,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    get_theme_mode,
    rag_colour,
)

# ── Shared layout defaults ──────────────────────────────────────────────────
# Plotly figures are Python objects, not HTML strings, so they aren't caught
# by the st.markdown light-theme patch in theme.py. _theme_text() below is
# called fresh inside every chart function (not frozen at import time) so
# charts pick up the current theme on every render.
_TRANSPARENT = "rgba(0,0,0,0)"
_HOVER_TEMPLATE_STYLE = "<extra></extra>"

_DEFAULT_HEIGHT = 350


def _theme_text() -> dict:
    """Fresh text/grid/hover colours for the currently active theme."""
    if get_theme_mode() == "light":
        return dict(
            primary="#1a1a2e",
            secondary="#4d4d6e",
            muted="#666688",
            grid="rgba(10,14,35,0.10)",
            hover_bg="rgba(255,255,255,0.96)",
            hover_border="rgba(10,14,35,0.12)",
            marker_line="rgba(255,255,255,0.9)",
        )
    return dict(
        primary=TEXT_PRIMARY,
        secondary=TEXT_SECONDARY,
        muted=TEXT_MUTED,
        grid="rgba(255,255,255,0.06)",
        hover_bg="rgba(17,22,56,0.92)",
        hover_border=BORDER_GLASS,
        marker_line="rgba(10,14,39,0.8)",
    )


def _base_layout(title: str, height: int = _DEFAULT_HEIGHT, **overrides) -> dict:
    """Return a reusable theme-aware layout dict."""
    t = _theme_text()
    font = dict(family="Inter, -apple-system, BlinkMacSystemFont, sans-serif", color=t["primary"])
    layout = dict(
        title=dict(text=title, font={**font, "size": 14, "color": t["secondary"]}, x=0, xanchor="left"),
        paper_bgcolor=_TRANSPARENT,
        plot_bgcolor=_TRANSPARENT,
        font=font,
        height=height,
        margin=dict(l=40, r=24, t=15, b=64),
        legend=dict(
            font=dict(size=11, color=t["secondary"]),
            bgcolor=_TRANSPARENT,
            borderwidth=0,
            orientation="h",
            yanchor="top",
            y=-0.15,
            xanchor="center",
            x=0.5,
        ),
        hoverlabel=dict(
            bgcolor=t["hover_bg"],
            bordercolor=t["hover_border"],
            font=dict(family="Inter", size=12, color=t["primary"]),
        ),
    )
    layout.update(overrides)
    return layout


def _axis_defaults(show_grid: bool = True) -> dict:
    """Common theme-aware axis styling."""
    t = _theme_text()
    return dict(
        gridcolor=t["grid"] if show_grid else _TRANSPARENT,
        zerolinecolor=t["grid"],
        tickfont=dict(size=11, color=t["muted"]),
        linecolor=_TRANSPARENT,
    )


# ── 1. Gauge Chart ──────────────────────────────────────────────────────────

def create_gauge_chart(
    value: float,
    title: str,
    max_val: float = 100,
    colour: str = ACCENT_BLUE,
    height: int = 250,
) -> go.Figure:
    """Radial gauge chart with RAG-coloured bar, no tick marks."""
    bar_colour = rag_colour(value) if max_val == 100 else colour
    t = _theme_text()
    font = dict(family="Inter, -apple-system, BlinkMacSystemFont, sans-serif", color=t["primary"])
    gauge_bg = "rgba(10,14,35,0.05)" if get_theme_mode() == "light" else "rgba(255,255,255,0.04)"

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=value,
            title=dict(text=title, font={**font, "size": 13, "color": t["secondary"]}),
            number=dict(font={**font, "size": 32}, suffix="", valueformat=".0f"),
            gauge=dict(
                axis=dict(range=[0, max_val], visible=False),
                bar=dict(color=bar_colour, thickness=0.75),
                bgcolor=gauge_bg,
                borderwidth=0,
                steps=[
                    dict(range=[0, max_val * 0.6], color="rgba(255,68,68,0.08)"),
                    dict(range=[max_val * 0.6, max_val * 0.8], color="rgba(255,170,0,0.08)"),
                    dict(range=[max_val * 0.8, max_val], color="rgba(0,255,136,0.08)"),
                ],
                threshold=dict(
                    line=dict(color=t["muted"], width=2),
                    thickness=0.8,
                    value=value,
                ),
            ),
        )
    )
    fig.update_layout(**_base_layout(title="", height=height, margin=dict(l=24, r=24, t=32, b=8)))
    return fig


# ── 2. Heatmap ──────────────────────────────────────────────────────────────

def create_heatmap(
    data: List[List[float]],
    x_labels: List[str],
    y_labels: List[str],
    title: str,
    colour_scale: str = "Blues",
) -> go.Figure:
    """Vulnerability heatmap with custom colour scale."""
    t = _theme_text()
    fig = go.Figure(
        go.Heatmap(
            z=data,
            x=x_labels,
            y=y_labels,
            colorscale=colour_scale,
            hovertemplate="X: %{x}<br>Y: %{y}<br>Value: %{z:.1f}" + _HOVER_TEMPLATE_STYLE,
            colorbar=dict(
                tickfont=dict(size=10, color=t["muted"]),
                outlinewidth=0,
                bgcolor=_TRANSPARENT,
            ),
        )
    )
    fig.update_layout(
        **_base_layout(title, height=_DEFAULT_HEIGHT),
        xaxis=_axis_defaults(show_grid=False),
        yaxis=_axis_defaults(show_grid=False),
    )
    return fig


# ── 3. Bar Chart ────────────────────────────────────────────────────────────

def create_bar_chart(
    categories: List[str],
    values: List[float],
    title: str,
    colour: str = ACCENT_BLUE,
    horizontal: bool = False,
) -> go.Figure:
    """Styled bar chart (vertical or horizontal)."""
    orientation = "h" if horizontal else "v"
    kwargs = dict(
        y=categories, x=values, orientation="h",
    ) if horizontal else dict(
        x=categories, y=values, orientation="v",
    )

    fig = go.Figure(
        go.Bar(
            **kwargs,
            marker=dict(
                color=colour,
                line=dict(width=0),
                cornerradius=6,
                opacity=0.85,
            ),
            hovertemplate="%{y}: %{x:.0f}" + _HOVER_TEMPLATE_STYLE
            if horizontal
            else "%{x}: %{y:.0f}" + _HOVER_TEMPLATE_STYLE,
        )
    )

    xax = _axis_defaults(show_grid=not horizontal)
    yax = _axis_defaults(show_grid=horizontal)
    fig.update_layout(**_base_layout(title), xaxis=xax, yaxis=yax)
    return fig


# ── 4. Donut Chart ──────────────────────────────────────────────────────────

def create_donut_chart(
    labels: List[str],
    values: List[float],
    title: str,
    colours: Optional[List[str]] = None,
) -> go.Figure:
    """Donut chart with hole=0.65, custom or auto colours."""
    t = _theme_text()
    palette = colours or [ACCENT_BLUE, ACCENT_RED, ACCENT_PURPLE, ACCENT_GREEN, RAG_AMBER, TEXT_MUTED]
    slice_border = "rgba(255,255,255,0.9)" if get_theme_mode() == "light" else "rgba(10,14,39,0.8)"

    fig = go.Figure(
        go.Pie(
            labels=labels,
            values=values,
            hole=0.65,
            marker=dict(colors=palette[: len(labels)], line=dict(color=slice_border, width=2)),
            textfont=dict(size=11, color=t["primary"]),
            textposition="outside",
            hovertemplate="%{label}: %{value} (%{percent})" + _HOVER_TEMPLATE_STYLE,
        )
    )
    fig.update_layout(**_base_layout(title, margin=dict(l=24, r=24, t=48, b=24)))
    return fig


# ── 5. Trend / Multi-series Line Chart ──────────────────────────────────────

def create_trend_chart(
    dates: List[str],
    series_dict: Dict[str, List[float]],
    title: str,
) -> go.Figure:
    """Multi-series line chart. series_dict = {name: values}."""
    palette = [ACCENT_BLUE, ACCENT_RED, ACCENT_PURPLE, ACCENT_GREEN, RAG_AMBER, TEXT_SECONDARY]
    fig = go.Figure()

    for idx, (name, vals) in enumerate(series_dict.items()):
        clr = palette[idx % len(palette)]
        fig.add_trace(
            go.Scatter(
                x=dates,
                y=vals,
                mode="lines+markers",
                name=name,
                line=dict(color=clr, width=2.5, shape="spline"),
                marker=dict(size=5, color=clr),
                hovertemplate=f"{name}: %{{y:.1f}}" + _HOVER_TEMPLATE_STYLE,
                fill="tozeroy",
                fillcolor=f"rgba({int(clr[1:3],16)},{int(clr[3:5],16)},{int(clr[5:7],16)},0.06)",
            )
        )

    fig.update_layout(
        **_base_layout(title),
        xaxis=_axis_defaults(),
        yaxis=_axis_defaults(),
    )
    return fig


# ── 6. Radar / Spider Chart ─────────────────────────────────────────────────

def create_radar_chart(
    categories: List[str],
    values: List[float],
    title: str,
    colour: str = ACCENT_BLUE,
) -> go.Figure:
    """Radar / spider chart for capability assessments."""
    cats_closed = list(categories) + [categories[0]]
    vals_closed = list(values) + [values[0]]

    fig = go.Figure(
        go.Scatterpolar(
            r=vals_closed,
            theta=cats_closed,
            fill="toself",
            fillcolor=f"rgba({int(colour[1:3],16)},{int(colour[3:5],16)},{int(colour[5:7],16)},0.15)",
            line=dict(color=colour, width=2.5),
            marker=dict(size=6, color=colour),
            hovertemplate="%{theta}: %{r:.0f}" + _HOVER_TEMPLATE_STYLE,
        )
    )

    t = _theme_text()
    fig.update_layout(
        **_base_layout(title, height=380),
        polar=dict(
            bgcolor=_TRANSPARENT,
            radialaxis=dict(
                visible=True,
                gridcolor=t["grid"],
                linecolor=_TRANSPARENT,
                tickfont=dict(size=9, color=t["muted"]),
            ),
            angularaxis=dict(
                gridcolor=t["grid"],
                linecolor=t["grid"],
                tickfont=dict(size=11, color=t["secondary"]),
            ),
        ),
    )
    return fig


# ── 7. ATT&CK Heatmap ──────────────────────────────────────────────────────

def create_attack_heatmap(
    techniques: List[str],
    tactics: List[str],
    values: List[List[float]],
    title: str,
) -> go.Figure:
    """MITRE ATT&CK heatmap grid (techniques × tactics)."""
    t = _theme_text()
    zero_colour = "rgba(10,14,35,0.06)" if get_theme_mode() == "light" else "rgba(10,14,39,0.6)"
    fig = go.Figure(
        go.Heatmap(
            z=values,
            x=tactics,
            y=techniques,
            colorscale=[
                [0.0, zero_colour],
                [0.25, "rgba(255,68,68,0.25)"],
                [0.5, "rgba(255,170,0,0.5)"],
                [0.75, "rgba(255,68,68,0.7)"],
                [1.0, "#ff2222"],
            ],
            hovertemplate="Tactic: %{x}<br>Technique: %{y}<br>Detections: %{z}" + _HOVER_TEMPLATE_STYLE,
            colorbar=dict(
                title=dict(text="Detections", font=dict(size=11, color=t["secondary"])),
                tickfont=dict(size=10, color=t["muted"]),
                outlinewidth=0,
                bgcolor=_TRANSPARENT,
            ),
            xgap=3,
            ygap=3,
        )
    )

    fig.update_layout(
        **_base_layout(title, height=max(350, len(techniques) * 28 + 80)),
        xaxis=dict(
            tickfont=dict(size=10, color=t["muted"]),
            tickangle=-45,
            side="bottom",
        ),
        yaxis=dict(
            tickfont=dict(size=10, color=t["muted"]),
            autorange="reversed",
        ),
    )
    return fig


# ── 8. Severity Distribution ────────────────────────────────────────────────

_SEV_COLOURS = {
    "Critical": "#ff2222",
    "High": ACCENT_RED,
    "Medium": RAG_AMBER,
    "Low": ACCENT_BLUE,
    "Info": TEXT_MUTED,
}


def create_severity_distribution(
    critical: int,
    high: int,
    medium: int,
    low: int,
    info: int = 0,
) -> go.Figure:
    """Stacked horizontal bar for severity distribution."""
    severities = [("Critical", critical), ("High", high), ("Medium", medium), ("Low", low)]
    if info:
        severities.append(("Info", info))

    fig = go.Figure()
    for sev, count in severities:
        fig.add_trace(
            go.Bar(
                y=["Findings"],
                x=[count],
                name=sev,
                orientation="h",
                marker=dict(color=_SEV_COLOURS[sev], opacity=0.9, cornerradius=4),
                text=[f"{sev}: {count}"],
                textposition="inside",
                textfont=dict(size=11, color="#ffffff", family="Inter"),
                hovertemplate=f"{sev}: {count}" + _HOVER_TEMPLATE_STYLE,
            )
        )

    fig.update_layout(
        **_base_layout("", height=100, margin=dict(l=8, r=8, t=8, b=8)),
        barmode="stack",
        showlegend=False,
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
    )
    return fig


# ── 9. Timeline Chart ───────────────────────────────────────────────────────

def create_timeline_chart(
    events: List[Dict[str, str]],
    title: str,
) -> go.Figure:
    """Timeline chart. events = [{timestamp, label, colour}, ...]."""
    t = _theme_text()
    marker_border = "rgba(255,255,255,0.9)" if get_theme_mode() == "light" else "rgba(10,14,39,0.8)"
    timestamps = [e["timestamp"] for e in events]
    labels = [e["label"] for e in events]
    colours = [e.get("colour", ACCENT_BLUE) for e in events]

    fig = go.Figure()

    # Connecting line
    fig.add_trace(
        go.Scatter(
            x=timestamps,
            y=[0] * len(timestamps),
            mode="lines",
            line=dict(color=t["grid"], width=2),
            showlegend=False,
            hoverinfo="skip",
        )
    )

    # Event markers
    fig.add_trace(
        go.Scatter(
            x=timestamps,
            y=[0] * len(timestamps),
            mode="markers+text",
            marker=dict(
                size=14,
                color=colours,
                line=dict(width=2, color=marker_border),
                symbol="circle",
            ),
            text=labels,
            textposition="top center",
            textfont=dict(size=10, color=t["secondary"]),
            hovertemplate="%{text}<br>%{x}" + _HOVER_TEMPLATE_STYLE,
            showlegend=False,
        )
    )

    fig.update_layout(
        **_base_layout(title, height=200, margin=dict(l=24, r=24, t=48, b=24)),
        xaxis=dict(
            tickfont=dict(size=10, color=t["muted"]),
            gridcolor=_TRANSPARENT,
            linecolor=_TRANSPARENT,
        ),
        yaxis=dict(visible=False, range=[-0.5, 1]),
    )
    return fig


# ── Attack path / vulnerability-chain diagram ───────────────────────────────

_CHAIN_SEVERITY_COLOUR = {
    "critical": RAG_RED,
    "high": ACCENT_RED,
    "medium": RAG_AMBER,
    "low": ACCENT_GREEN,
}


def render_attack_chain_diagram(chains: List[dict], accent: str = ACCENT_BLUE) -> str:
    """Render one or more multi-hop attack/vulnerability chains as an HTML node-and-arrow diagram.

    Each chain is {"chain_id", "severity", "steps": [{"asset", "technique_or_cve", "note"}]}.
    Returns an HTML string for st.markdown(..., unsafe_allow_html=True).
    """
    if not chains:
        return ""

    blocks = []
    for chain in chains:
        chain_id = chain.get("chain_id", "CHAIN")
        severity = str(chain.get("severity", "High"))
        sev_colour = _CHAIN_SEVERITY_COLOUR.get(severity.lower(), RAG_AMBER)
        steps = chain.get("steps", [])

        step_nodes = []
        for i, step in enumerate(steps):
            asset = step.get("asset", "unknown asset")
            tech = step.get("technique_or_cve", "")
            note = step.get("note", "")
            node_html = f"""
            <div style="
                flex: 1; min-width: 180px;
                background: rgba(17, 22, 56, 0.5);
                border: 1px solid {BORDER_GLASS};
                border-top: 3px solid {sev_colour};
                border-radius: 10px;
                padding: 12px 14px;
            ">
                <div style="font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.05em; color: {TEXT_MUTED}; font-weight: 700; margin-bottom: 4px;">
                    Hop {i + 1}
                </div>
                <div style="font-size: 0.85rem; font-weight: 700; color: #ffffff; margin-bottom: 2px;">{asset}</div>
                <div style="font-size: 0.75rem; color: {sev_colour}; font-weight: 600; margin-bottom: 6px; font-family: 'JetBrains Mono', monospace;">{tech}</div>
                <div style="font-size: 0.75rem; color: {TEXT_SECONDARY}; line-height: 1.4;">{note}</div>
            </div>
            """
            step_nodes.append(node_html)
            if i < len(steps) - 1:
                step_nodes.append(
                    f'<div style="display:flex; align-items:center; padding: 0 6px; color: {accent}; font-size: 1.3rem; font-weight: 700;">&rarr;</div>'
                )

        blocks.append(f"""
        <div style="
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid {BORDER_GLASS};
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 12px;
        ">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 12px;">
                <span style="font-size: 0.8rem; font-weight: 700; color: {TEXT_SECONDARY}; font-family: 'JetBrains Mono', monospace;">{chain_id}</span>
                <span style="display:inline-block; padding: 2px 10px; border-radius: 10px; font-size: 0.68rem; font-weight: 700; background: {sev_colour}22; color: {sev_colour}; border: 1px solid {sev_colour}55;">{severity.upper()} CHAIN</span>
            </div>
            <div style="display:flex; align-items:stretch; flex-wrap:wrap; gap: 4px;">
                {''.join(step_nodes)}
            </div>
        </div>
        """)

    return "\n".join(blocks)
