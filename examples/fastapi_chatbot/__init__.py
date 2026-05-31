"""FastAPI demo target — vanilla HTTP chatbot with no framework.

The simplest possible target shape: a FastAPI app with a single ``/chat``
endpoint that accepts ``{"input": "<prompt>"}`` and returns
``{"output": "<text>"}``. Used to exercise the ``--endpoint`` mode
against an HTTP/JSON agent that does not use any agent framework.
"""
