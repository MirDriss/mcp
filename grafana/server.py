from mcp.server.fastmcp import FastMCP
mcp = FastMCP("grafana")  

if __name__ == "__main__":
    mcp.run(transport="stdio")