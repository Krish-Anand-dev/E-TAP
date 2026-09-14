"""
API integration test for POST /chat endpoint
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncio
from unittest.mock import MagicMock
from app import chat, ChatRequest, health


class TestApiChat(unittest.TestCase):

    def test_health_endpoint(self):
        resp = health()
        self.assertEqual(resp, {"status": "ok"})

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
