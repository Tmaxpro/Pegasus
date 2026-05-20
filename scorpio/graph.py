"""Compile the Scorpio LangGraph workflow.

Topology:

```
                    ┌──────────┐
                    │ analyst  │  (one-shot: build api_inventory)
                    └────┬─────┘
                         ▼
                    ┌──────────┐  ◄────────────────────┐
                    │supervisor│                       │
                    └────┬─────┘                       │
            ┌────────────┴─────────────┐               │
            ▼ (current_mission != None) ▼ (else)        │
       ┌─────────┐                  ┌─────────┐         │
       │ attacker│                  │ reporter│─► END   │
       └────┬────┘                  └─────────┘         │
            ▼                                           │
       ┌─────────┐                                      │
       │ auditor │──────────────────────────────────────┘
       └─────────┘
```

The conditional edge from ``supervisor`` is the only branching point — every
other edge is unconditional.

Persistence:
    The compiled graph is wrapped in a SqliteSaver checkpointer so a run can
    be resumed after a crash. The checkpoint file lives under
    ``checkpoints/scorpio.sqlite``.
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from typing import Iterator

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from scorpio.agents import (
    analyst_node,
    attacker_node,
    auditor_node,
    reporter_node,
    supervisor_node,
    supervisor_router,
)
from scorpio.config import get_settings
from scorpio.state import ScannerState

logger = logging.getLogger(__name__)


def build_graph() -> StateGraph:
    """Wire the five agent nodes into a StateGraph (not yet compiled)."""
    graph = StateGraph(ScannerState)

    graph.add_node("analyst", analyst_node)
    graph.add_node("supervisor", supervisor_node)
    graph.add_node("attacker", attacker_node)
    graph.add_node("auditor", auditor_node)
    graph.add_node("reporter", reporter_node)

    graph.add_edge(START, "analyst")
    graph.add_edge("analyst", "supervisor")
    graph.add_conditional_edges(
        "supervisor",
        supervisor_router,
        {
            "attacker": "attacker",
            "reporter": "reporter",
        },
    )
    graph.add_edge("attacker", "auditor")
    graph.add_edge("auditor", "supervisor")  # cycle back for the next mission
    graph.add_edge("reporter", END)

    return graph


@contextmanager
def compiled_graph() -> Iterator[CompiledStateGraph]:
    """Yield a compiled graph wired to the SqliteSaver checkpointer.

    Usage::

        with compiled_graph() as app:
            app.invoke(initial_state, config={"configurable": {"thread_id": "..."}})

    The context manager ensures the underlying SQLite connection is closed
    cleanly even if the run raises.
    """
    settings = get_settings()
    settings.ensure_runtime_dirs()
    logger.info("[graph] using checkpoint DB at %s", settings.checkpoint_db)

    # check_same_thread=False is required because LangGraph may dispatch node
    # invocations onto worker threads.
    conn = sqlite3.connect(str(settings.checkpoint_db), check_same_thread=False)
    try:
        checkpointer = SqliteSaver(conn)
        app = build_graph().compile(checkpointer=checkpointer)
        yield app
    finally:
        conn.close()
