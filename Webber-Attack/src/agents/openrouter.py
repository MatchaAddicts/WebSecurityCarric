"""
OpenRouter API Client
Unified interface for Claude and Moonshot models
"""

import os
import requests
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

load_dotenv()


class OpenRouterClient:
    """
    OpenRouter API wrapper
    2 agents: Claude (scanner_1) and Moonshot (scanner_2)
    """
    
    def __init__(self):
        self.api_key = os.getenv("OPENROUTER_API_KEY")
        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY not found in environment")
        
        self.base_url = "https://openrouter.ai/api/v1/chat/completions"
        
        # 2 scanners only
        self.models = {
            "brain": os.getenv("MODEL_BRAIN", "anthropic/claude-sonnet-4"),
            "scanner_1": os.getenv("MODEL_SCANNER_1", "anthropic/claude-sonnet-4"),
            "scanner_2": os.getenv("MODEL_SCANNER_2", "Moonshot/Moonshot-chat")
        }
        
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://webber-attack.local",
            "X-Title": "Webber-Attack Scanner"
        }
    
    def chat(self, model_key: str, messages: List[Dict[str, str]], temperature: float = 0.7) -> Dict[str, Any]:
        """
        Send chat request to OpenRouter
        
        Args:
            model_key: Key from self.models (brain, scanner_1, scanner_2)
            messages: List of message dicts with role and content
            temperature: Sampling temperature
            
        Returns:
            Dict with success status and content or error
        """
        model = self.models.get(model_key)
        if not model:
            return {"success": False, "error": f"Unknown model key: {model_key}"}
        
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": 4096
        }
        
        try:
            response = requests.post(
                self.base_url,
                headers=self.headers,
                json=payload,
                timeout=120
            )
            
            if response.status_code == 200:
                data = response.json()
                content = data["choices"][0]["message"]["content"]
                return {"success": True, "content": content}
            else:
                return {
                    "success": False, 
                    "error": f"API error {response.status_code}: {response.text[:500]}"
                }
                
        except requests.exceptions.Timeout:
            return {"success": False, "error": "Request timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def chat_brain(self, messages: List[Dict[str, str]], temperature: float = 0.7) -> Dict[str, Any]:
        """Shortcut for brain/orchestrator"""
        return self.chat("brain", messages, temperature)
    
    def chat_scanner(self, scanner_num: int, messages: List[Dict[str, str]], temperature: float = 0.7) -> Dict[str, Any]:
        """Shortcut for scanners (1=Claude, 2=Moonshot)"""
        return self.chat(f"scanner_{scanner_num}", messages, temperature)


# Test
if __name__ == "__main__":
    client = OpenRouterClient()
    print("OpenRouter client initialized")
    print(f"Models: {client.models}")
    
    # Quick test
    response = client.chat_scanner(1, [{"role": "user", "content": "Say 'Claude scanner ready' in 5 words or less"}])
    print(f"Scanner 1 (Claude): {response}")
    
    response = client.chat_scanner(2, [{"role": "user", "content": "Say 'Moonshot scanner ready' in 5 words or less"}])
    print(f"Scanner 2 (Moonshot): {response}")