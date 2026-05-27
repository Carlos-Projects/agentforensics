Quickstart
==========

Installation
------------

.. code-block:: bash

   pip install agentforensics

CLI usage
---------

.. code-block:: bash

   # Ingest logs
   agentforensics ingest --mcpguard /var/log/mcpguard.jsonl

   # Reconstruct timeline
   agentforensics timeline

   # Generate report
   agentforensics report --format markdown --output report.md

   # Start web dashboard
   agentforensics serve --port 8000

Python API
----------

.. code-block:: python

   from agentforensics.engine import ForensicsEngine
   from pathlib import Path

   engine = ForensicsEngine()
   engine.ingest_mcpguard(Path("mcpguard.jsonl"))
   timeline = engine.build_timeline()
   report = engine.generate_report(fmt="markdown")
   print(report)
