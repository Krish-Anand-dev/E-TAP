"""
API integration test for POST /chat endpoint
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncio
from unittest.mock import MagicMock
from app import chat, ChatRequest, health, ready, root


class TestApiChat(unittest.TestCase):

    def test_health_endpoint(self):
        resp = health()
        self.assertEqual(resp, {"status": "ok", "check": "liveness"})

    def test_root_service_index(self):
        resp = root()
        self.assertEqual(resp["status"], "online")
        self.assertEqual(resp["health"], "/health")
        self.assertEqual(resp["readiness"], "/ready")

    def test_ready_endpoint_with_database(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {"USE_FAKE_DB": "1"}, clear=False), \
             patch("db.connection.get_db", return_value=object()):
            resp = ready()
        self.assertEqual(resp["status"], "ready")
        self.assertEqual(resp["checks"]["database"], "in_memory_fake")

    def test_ready_endpoint_fails_closed_when_database_is_unavailable(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {"USE_FAKE_DB": "0"}, clear=False), \
             patch("db.connection.get_db", side_effect=RuntimeError("connection details must not leak")):
            resp = ready()
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.body, b'{"status":"not_ready","checks":{"database":"unavailable"}}')

    def test_chat_endpoint_valid_question(self):
        from starlette.requests import Request
        scope = {"type": "http", "method": "POST", "path": "/chat", "headers": [], "client": ("127.0.0.1", 1234)}
        req = Request(scope)
        payload = ChatRequest(question="Did we see any payroll phishing attacks?")
        data = asyncio.run(chat(req, payload))
        self.assertIn("answer", data)
        self.assertIn("sources", data)
        self.assertIn("retrieved_count", data)
        self.assertIsInstance(data["answer"], str)
        self.assertIsInstance(data["sources"], list)


if __name__ == "__main__":
    unittest.main()
