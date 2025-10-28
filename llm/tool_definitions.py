"""
MCP Tool Definitions
Schema definitions for MCP tools that Ollama can use
"""

# Tool definitions in Ollama format
OLLAMA_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "update_profile",
            "description": "Update user profile information in the system cache",
            "parameters": {
                "type": "object",
                "properties": {
                    "user_id": {
                        "type": "integer",
                        "description": "The user's unique identifier"
                    },
                    "bio": {
                        "type": "string",
                        "description": "The user's biography or profile description"
                    }
                },
                "required": ["user_id", "bio"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write content to a file in the storage system",
            "parameters": {
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Path where the file should be written"
                    },
                    "content": {
                        "type": "string",
                        "description": "Content to write to the file"
                    }
                },
                "required": ["filepath", "content"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "save_note",
            "description": "Save a note to the cache for later retrieval",
            "parameters": {
                "type": "object",
                "properties": {
                    "note_id": {
                        "type": "string",
                        "description": "Unique identifier for the note"
                    },
                    "content": {
                        "type": "string",
                        "description": "The note content"
                    }
                },
                "required": ["note_id", "content"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_profile",
            "description": "Retrieve user profile information from cache",
            "parameters": {
                "type": "object",
                "properties": {
                    "user_id": {
                        "type": "integer",
                        "description": "The user's unique identifier"
                    }
                },
                "required": ["user_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read content from a file in storage",
            "parameters": {
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Path to the file to read"
                    }
                },
                "required": ["filepath"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_note",
            "description": "Retrieve a previously saved note from cache",
            "parameters": {
                "type": "object",
                "properties": {
                    "note_id": {
                        "type": "string",
                        "description": "Unique identifier for the note"
                    }
                },
                "required": ["note_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_stats",
            "description": "Get storage statistics (cache and file system)",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    }
]


def get_tools_for_ollama():
    """Get tool definitions formatted for Ollama"""
    return OLLAMA_TOOLS