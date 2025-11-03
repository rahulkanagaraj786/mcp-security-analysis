"""
Ollama LLM Client
Integrates Ollama LLM with MCP tools

This simulates how a real LLM would use MCP to call tools
"""

import requests
import json
from typing import Dict, Any, Optional, List


class OllamaLLM:
    """
    Ollama LLM client that uses MCP tools
    
    Flow:
    User Query → Ollama (decides which tool) → MCP Client → MCP Server
    """
    
    def __init__(self, mcp_client, model: str = "llama3.1", base_url: str = "http://localhost:11434"):
        """
        Initialize Ollama client
        
        Args:
            mcp_client: MCP client instance to call tools
            model: Ollama model name (default: llama3.1)
            base_url: Ollama server URL
        """
        self.mcp_client = mcp_client
        self.model = model
        self.base_url = base_url
        self.conversation_history = []
        
        # Check if Ollama is running
        try:
            response = requests.get(f"{base_url}/api/tags", timeout=2)
            if response.status_code == 200:
                print(f"[OllamaLLM] Connected to Ollama at {base_url}")
                print(f"[OllamaLLM] Using model: {model}")
            else:
                print(f"[OllamaLLM] Warning: Ollama responded with status {response.status_code}")
        except Exception as e:
            print(f"[OllamaLLM] ERROR: Cannot connect to Ollama at {base_url}")
            print(f"[OllamaLLM] Make sure Ollama is running: ollama serve")
            raise ConnectionError(f"Cannot connect to Ollama: {e}")
    
    async def process_query(self, user_query: str, tools: Optional[List[Dict]] = None) -> Dict[str, Any]:
        """
        Process user query with Ollama
        
        Args:
            user_query: Natural language query from user
            tools: List of available MCP tools
        
        Returns:
            Dict with LLM response and any tool calls made
        """
        print(f"\n{'='*60}")
        print(f"👤 User Query: {user_query}")
        print(f"{'='*60}\n")
        
        # Add user message to history
        self.conversation_history.append({
            "role": "user",
            "content": user_query
        })
        
        # Prepare request to Ollama
        payload = {
            "model": self.model,
            "messages": self.conversation_history,
            "stream": False
        }
        
        # Add tools if provided
        if tools:
            payload["tools"] = tools
            print(f"🔧 Available tools: {[t['function']['name'] for t in tools]}\n")
        
        try:
            # Send to Ollama
            print(f"🤖 Sending query to Ollama ({self.model})...")
            response = requests.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=120
            )
            response.raise_for_status()
            
            result = response.json()
            message = result.get("message", {})
            
            # Add assistant response to history
            self.conversation_history.append(message)
            
            # Check if LLM wants to use a tool
            if "tool_calls" in message:
                print(f"🤖 Ollama wants to use tools!\n")
                return await self._handle_tool_calls(message["tool_calls"], user_query)
            else:
                # Regular text response
                text_response = message.get("content", "")
                print(f"🤖 Ollama Response: {text_response}\n")
                return {
                    "type": "text",
                    "response": text_response,
                    "query": user_query
                }
        
        except requests.exceptions.Timeout:
            print(f" Ollama request timed out")
            return {"error": "Ollama timeout"}
        except Exception as e:
            print(f" Error communicating with Ollama: {e}")
            return {"error": str(e)}
    
    async def _handle_tool_calls(self, tool_calls: List[Dict], user_query: str) -> Dict[str, Any]:
        """
        Handle tool calls from Ollama
        
        Args:
            tool_calls: List of tool calls from Ollama
            user_query: Original user query
        
        Returns:
            Dict with tool call results
        """
        results = []
        
        for tool_call in tool_calls:
            function = tool_call.get("function", {})
            tool_name = function.get("name")
            
            # Parse arguments (might be string or dict)
            arguments = function.get("arguments", {})
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    print(f"⚠️  Could not parse arguments: {arguments}")
                    arguments = {}
            
            print(f"🔧 Tool Call: {tool_name}")
            print(f"   Arguments: {json.dumps(arguments, indent=2)}\n")
            
            # Call MCP tool via client
            try:
                print(f" Calling MCP Server...")
                tool_result = await self.mcp_client.call_tool(tool_name, arguments)
                
                print(f" MCP Server Response:")
                print(f"   {json.dumps(tool_result, indent=2)}\n")
                
                results.append({
                    "tool": tool_name,
                    "arguments": arguments,
                    "result": tool_result,
                    "success": True
                })
            
            except Exception as e:
                print(f" Error calling tool {tool_name}: {e}\n")
                results.append({
                    "tool": tool_name,
                    "arguments": arguments,
                    "error": str(e),
                    "success": False
                })
        
        return {
            "type": "tool_use",
            "query": user_query,
            "tool_calls": results
        }
    
    def simple_query(self, user_query: str) -> str:
        """
        Simple query without tools (just text response)
        
        Args:
            user_query: Question for the LLM
        
        Returns:
            Text response from LLM
        """
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": user_query,
                    "stream": False
                },
                timeout=30
            )
            response.raise_for_status()
            
            result = response.json()
            return result.get("response", "")
        
        except Exception as e:
            return f"Error: {e}"
    
    def clear_history(self):
        """Clear conversation history"""
        self.conversation_history = []
        print("[OllamaLLM] Conversation history cleared")