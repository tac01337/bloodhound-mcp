# Bloodhound-MCP

Bloodhound-MCP is a server implementation for Bloodhound's API. It provides a backend service to handle requests and manage data for the Bloodhound application.

## Features
- Implements the API for Bloodhound.
- Handles data management and request processing.
- Designed for scalability and reliability.

## Requirements
- Linux operating system.
- Python 3.6 or higher.

## Installation
1. Clone the repository:
   ```bash
   git clone <repository-url>
   ```
2. Navigate to the project directory:
   ```bash
   cd bloodhound-mcp
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run with FastMCP:
    ```bash
    fastmcp run bloodhound_server.py
    ```


## Testing
1. Test with MCP inspector using FastMCP
    ```bash
    fastmcp dev bloodhound_server.py
    ```

## Usage
Run the server using the following command:
```bash
uv run --with fastmcp fastmcp run bloodhound_server.py
```

## Contributing
Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Submit a pull request with a detailed description of your changes.

## License
This project is licensed under the terms of the LICENSE file included in the repository.

## Contact
For questions or support, please open an issue in the repository.
