"""RAG demo target — a retrieval-augmented chatbot exposed over HTTP.

The retriever is a tiny canned dictionary so the demo is hermetic. The
generator is a stub that returns a deterministic answer string. The
relevant attack surface for AgentGuardian is the prompt-concatenation
boundary: attacker-controlled content in retrieved chunks must not be
treated as instructions.
"""
