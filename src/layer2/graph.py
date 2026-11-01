from langgraph.graph import END, START, StateGraph

from .state import AgentState


workflow = StateGraph(AgentState)
workflow.add_edge(START, END)
graph = workflow.compile()