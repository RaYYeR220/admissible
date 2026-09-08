"""The graph.

    perceive -> recall -> admit -> decide -> act -> attest -> reflect -> consolidate

A straight line, no branches. That is a design decision rather than a
simplification: every run does the same eight things in the same order, so the
trace of a payment and the trace of a refusal differ only in what the nodes
found, never in which nodes ran. A conditional edge that skips ``attest`` on a
refusal would be the natural optimisation and it would delete the record of the
attack.

The graph is compiled with ``SibylStore`` as its store. There is no
checkpointer: ``SibylStore`` is a long-term ``BaseStore`` and not one, and each
run of this graph is a single synchronous pass with nothing worth resuming. The
memory that matters here is cross-run, cross-process memory, which is exactly
what the store provides and what a checkpointer would not.
"""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph
from langgraph.store.base import BaseStore

from .nodes import AgentDeps, build_nodes
from .state import BuyerState

#: The order, declared once, so the graph and the docs cannot disagree.
NODE_ORDER = (
    "perceive",
    "recall",
    "admit",
    "decide",
    "act",
    "attest",
    "reflect",
    "consolidate",
)


def build_graph(deps: AgentDeps, store: BaseStore):
    """Compile the buyer graph against a LangGraph store.

    ``store`` is a ``BaseStore`` and is typed as one here on purpose: the graph
    does not know it is talking to Sibyl Memory, and the nodes reach it through
    LangGraph's injection rather than through the closure, which is what makes
    the adapter load-bearing instead of decorative.
    """
    nodes = build_nodes(deps)
    graph = StateGraph(BuyerState)
    for name in NODE_ORDER:
        graph.add_node(name, nodes[name])
    graph.add_edge(START, NODE_ORDER[0])
    for earlier, later in zip(NODE_ORDER, NODE_ORDER[1:]):
        graph.add_edge(earlier, later)
    graph.add_edge(NODE_ORDER[-1], END)
    return graph.compile(store=store)
