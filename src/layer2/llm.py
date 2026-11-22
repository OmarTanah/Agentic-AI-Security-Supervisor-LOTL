import os

from dotenv import load_dotenv
from langchain_core.runnables import Runnable
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_groq import ChatGroq
from pydantic import SecretStr


def get_llm() -> Runnable:
    """Create the Groq-first model chain with ordered fallbacks."""
    load_dotenv()
    groq_api_key = os.getenv("GROQ_API_KEY")
    groq_secret = SecretStr(groq_api_key) if groq_api_key else None
    models = [
        ChatGroq(
            model="llama-3.3-70b-versatile",
            temperature=0.1,
            api_key=groq_secret,
            timeout=15,
        ),
        ChatGroq(
            model="llama-3.1-8b-instant",
            temperature=0.1,
            api_key=groq_secret,
            timeout=15,
        ),
        ChatGroq(
            model="meta-llama/llama-4-scout-17b-16e-instruct",
            temperature=0.1,
            api_key=groq_secret,
            timeout=15,
        ),
        ChatGroq(
            model="meta-llama/llama-4-maverick-17b-128e-instruct",
            temperature=0.1,
            api_key=groq_secret,
            timeout=15,
        ),
        ChatGroq(
            model="openai/gpt-oss-120b",
            temperature=0.1,
            api_key=groq_secret,
            timeout=15,
        ),
        ChatGroq(
            model="openai/gpt-oss-20b",
            temperature=0.1,
            api_key=groq_secret,
            timeout=15,
        ),
        ChatGroq(
            model="gemma2-9b-it",
            temperature=0.1,
            api_key=groq_secret,
            timeout=15,
        ),
        ChatGroq(
            model="mixtral-8x7b-32768",
            temperature=0.1,
            api_key=groq_secret,
            timeout=15,
        ),
        ChatGoogleGenerativeAI(
            model="gemini-3.5-flash-lite",
            temperature=0.1,
            api_key=os.getenv("GOOGLE_API_KEY"),
            timeout=15,
        ),
        ChatGoogleGenerativeAI(
            model="gemini-3.1-flash-lite",
            temperature=0.1,
            api_key=os.getenv("GOOGLE_API_KEY"),
            timeout=15,
        ),
    ]
    return models[0].with_fallbacks(models[1:])