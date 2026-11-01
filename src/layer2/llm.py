import os

from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI


def get_llm() -> ChatGoogleGenerativeAI:
    """Create the configured Gemini chat model from the local environment."""
    load_dotenv()
    return ChatGoogleGenerativeAI(
        model="gemini-3.8-flash",
        temperature=0.1,
        api_key=os.getenv("GOOGLE_API_KEY"),
    )