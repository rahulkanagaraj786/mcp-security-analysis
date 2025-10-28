"""
Basic Vulnerable MCP Server - Simple SSRF vulnerability for testing
"""
import asyncio
import logging
import requests
from typing import Any, Dict, List
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequest,
    CallToolResult,
    ListToolsRequest,
    ListToolsResult,
    Tool,
    TextContent,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BasicVulnerableMCPServer:
    def __init__(self):
        self.server = Server("basic-vulnerable-mcp-server")
        self.setup_tools()
        
    def setup_tools(self):
        """Register vulnerable tools"""
        
        @self.server.list_tools()
        async def list_tools() -> ListToolsResult:
            """List available tools"""
            return ListToolsResult(
                tools=[
                    Tool(
                        name="fetch_url",
                        description="Fetch content from any URL - VULNERABLE TO SSRF",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "url": {
                                    "type": "string",
                                    "description": "URL to fetch content from"
                                }
                            },
                            "required": ["url"]
                        }
                    ),
                    Tool(
                        name="get_weather",
                        description="Get weather information for a city",
                        inputSchema={
                            "type": "object",
                            "properties": {
                                "city": {
                                    "type": "string",
                                    "description": "City name to get weather for"
                                }
                            },
                            "required": ["city"]
                        }
                    )
                ]
            )

        @self.server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> CallToolResult:
            """Execute tools"""
            
            if name == "fetch_url":
                return await self.vulnerable_fetch_url(arguments)
            elif name == "get_weather":
                return await self.vulnerable_get_weather(arguments)
            else:
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Unknown tool: {name}")]
                )

    async def vulnerable_fetch_url(self, arguments: Dict[str, Any]) -> CallToolResult:
        """VULNERABLE: No URL validation - allows SSRF attacks"""
        url = arguments.get("url", "")
        
        logger.warning(f"VULNERABLE: Fetching URL without validation: {url}")
        
        try:
            # VULNERABILITY: Direct requests.get without any validation
            response = requests.get(url, timeout=10)
            return CallToolResult(
                content=[
                    TextContent(
                        type="text", 
                        text=f"Status: {response.status_code}\nContent: {response.text[:1000]}..."
                    )
                ]
            )
        except Exception as e:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Error fetching URL: {str(e)}")]
            )

    async def vulnerable_get_weather(self, arguments: Dict[str, Any]) -> CallToolResult:
        """VULNERABLE: Weather service that can be exploited for SSRF"""
        city = arguments.get("city", "")
        
        logger.warning(f"VULNERABLE: Getting weather for city: {city}")
        
        # This simulates a weather service that might be vulnerable to SSRF
        # In a real scenario, this might construct URLs based on user input
        weather_url = f"http://api.weather.com/v1/current?city={city}"
        
        try:
            response = requests.get(weather_url, timeout=10)
            return CallToolResult(
                content=[
                    TextContent(
                        type="text", 
                        text=f"Weather for {city}:\nStatus: {response.status_code}\nContent: {response.text[:500]}..."
                    )
                ]
            )
        except Exception as e:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Error getting weather: {str(e)}")]
            )

async def main():
    """Run the basic vulnerable MCP server"""
    vulnerable_server = BasicVulnerableMCPServer()
    
    logger.info("Starting Basic Vulnerable MCP Server...")
    logger.warning("WARNING: This server is intentionally vulnerable for security testing!")
    
    async with stdio_server() as (read_stream, write_stream):
        await vulnerable_server.server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="basic-vulnerable-mcp-server",
                server_version="1.0.0",
                capabilities=vulnerable_server.server.get_capabilities(
                    notification_options=None,
                    experimental_capabilities=None,
                ),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())
