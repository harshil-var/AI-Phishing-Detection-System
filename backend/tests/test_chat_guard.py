import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.chatbot_service import is_security_related, get_chatbot_response, RESTRICTED_GUARD_MESSAGE

def test_chat_guard_allows_security_topics():
    assert is_security_related("How do I recognize a phishing email?") == True
    assert is_security_related("What should I do after clicking a suspicious link?") == True
    assert is_security_related("How does HTTPS protect my password?") == True

def test_chat_guard_blocks_out_of_domain_topics():
    assert is_security_related("Write me a Python program.") == False
    assert is_security_related("Who is Elon Musk?") == False
    assert is_security_related("Tell me a joke.") == False
    assert is_security_related("Solve this mathematics question.") == False
    assert is_security_related("Write an essay about India.") == False

def test_chat_guard_response_restriction():
    res = get_chatbot_response("Tell me a joke.")
    assert res["allowed"] == False
    assert res["topic_blocked"] == True
    assert res["response"] == RESTRICTED_GUARD_MESSAGE
