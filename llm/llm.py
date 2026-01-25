from google import genai
import os
from dotenv import load_dotenv

load_dotenv("variables.env")

class GeminiClient:
    def __init__(self, model_name: str = "models/gemini-2.5-flash"):
        self.client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
        self.model_name = model_name

    def analyze(self, prompt: str) -> str:
        response = self.client.models.generate_content(
            model=self.model_name,
            contents=prompt,
            generation_config={
                "temperature": 0.2,
                "top_p": 0.9,
                "max_output_tokens": 800,
            }
        )
        return response.text