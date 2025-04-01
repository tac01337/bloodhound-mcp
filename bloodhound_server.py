# bloodhound_server.py

from fastmcp import FastMCP, Context
import httpx
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

# Create the FastMCP server
mcp = FastMCP("BloodHound Explorer")

# Define models for BloodHound data
class NodeIdentifier(BaseModel):
    name: str = Field(..., description="Name of the node, like 'username@domain.com' or 'computername.domain.com'")

class QueryParams(BaseModel):
    query: str = Field(..., description="Cypher query to execute against BloodHound")

class PathRequest(BaseModel):
    start_node: str = Field(..., description="Starting node name or SID")
    end_node: str = Field(..., description="Target node name or SID")
    node_type: Optional[str] = Field(None, description="Node type filter (User, Computer, Group, etc.)")

class AttackPathsParams(BaseModel):
    target: str = Field(..., description="Target node name or SID")
    source: Optional[str] = Field(None, description="Source node (default: any owned nodes)")
    include_edges: Optional[List[str]] = Field(None, description="Edge types to include")
    exclude_edges: Optional[List[str]] = Field(None, description="Edge types to exclude")

# Configuration resource
@mcp.resource("bloodhound://config")
def get_config() -> str:
    """Get configuration information for the BloodHound server"""
    config = {
        "api_base_url": "http://localhost:8080/api/v2",
        "supported_edge_types": [
            "MemberOf", "HasSession", "AdminTo", "CanRDP", 
            "ExecuteDCOM", "AllowedToDelegate", "AddAllowedToAct",
            "GenericAll", "GenericWrite", "WriteDACL", "WriteOwner",
            "AddMember", "ForceChangePassword", "ReadLAPSPassword",
            "ReadGMSAPassword", "Contains", "GPLink", "AddSelf",
            "DCSync", "GetChanges", "GetChangesAll", "ADCSESC1"
        ]
    }
    
    return f"""
# BloodHound Configuration

API Base URL: {config['api_base_url']}

## Supported Edge Types
{', '.join(config['supported_edge_types'])}

To use this server, set the following environment variables:
- BH_API_URL: BloodHound API URL (default: http://localhost:8080/api/v2)
- BH_USERNAME: BloodHound username
- BH_PASSWORD: BloodHound password
- BH_TOKEN: BloodHound API token (alternative to username/password)
"""

# Helper function to create API client
async def get_api_client(ctx: Context) -> httpx.AsyncClient:
    """Create and return an authenticated API client for BloodHound"""
    # You would implement actual authentication here
    # For now, we'll just use a basic httpx client
    return httpx.AsyncClient(
        base_url="http://localhost:8080/api/v2",
        headers={"Authorization": "Bearer TOKEN"}
    )

# Tools for interacting with BloodHound

@mcp.tool()
async def find_shortest_path(params: PathRequest, ctx: Context) -> Dict[str, Any]:
    """
    Find the shortest attack path between two entities in the environment.
    
    This tool uses BloodHound's pathfinding functionality to identify the shortest
    path between two entities, showing how an attacker could potentially move
    from one to the other through identity relationships.
    """
    client = await get_api_client(ctx)
    
    try:
        ctx.info(f"Finding shortest path from {params.start_node} to {params.end_node}")
        
        # This is an example that would need to be modified based on actual API
        response = await client.post("/paths/shortest", json={
            "start": params.start_node,
            "end": params.end_node,
            "nodeType": params.node_type
        })
        response.raise_for_status()
        result = response.json()
        
        # Add some helpful context to the result
        if "paths" in result and len(result["paths"]) > 0:
            ctx.info(f"Found {len(result['paths'])} path(s)")
            return {
                "success": True,
                "path_count": len(result["paths"]),
                "paths": result["paths"],
                "analysis": "Attack path found - see details for node relationships"
            }
        else:
            return {
                "success": True,
                "path_count": 0,
                "paths": [],
                "analysis": "No attack paths found between these nodes"
            }
    
    except Exception as e:
        ctx.error(f"Error finding path: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@mcp.tool()
async def search_entities(search_term: str, entity_type: Optional[str] = None, ctx: Context) -> List[Dict[str, Any]]:
    """
    Search for entities in BloodHound by name or partial name.
    
    Args:
        search_term: The search string (e.g., "jsmith", "domain admins")
        entity_type: Optional type filter (User, Computer, Group, Domain, OU, GPO)
    
    Returns:
        A list of matching entities with their properties
    """
    client = await get_api_client(ctx)
    
    try:
        params = {"q": search_term}
        if entity_type:
            params["type"] = entity_type
            
        ctx.info(f"Searching for '{search_term}' with type filter: {entity_type}")
        response = await client.get("/search", params=params)
        response.raise_for_status()
        
        return response.json()
    
    except Exception as e:
        ctx.error(f"Error searching entities: {str(e)}")
        return [{"error": str(e)}]

@mcp.tool()
async def run_analysis_query(query_name: str, ctx: Context) -> Dict[str, Any]:
    """
    Run a pre-defined security analysis query in BloodHound.
    
    Args:
        query_name: Name of the analysis query to run
        
    Available queries:
        - find_domain_admins: Find all Domain Admin users
        - kerberoastable_users: Find users vulnerable to Kerberoasting
        - high_value_targets: Identify high-value targets in the environment
        - domain_trust_mapping: Map domain trusts in the environment
        - path_to_domain_admin: Find users with a path to Domain Admin
        - unprotected_ous: Find OUs without proper protection
        - adcs_vulnerable_templates: Find vulnerable certificate templates
    
    Returns:
        The results of the analysis
    """
    # Mapping of friendly names to query endpoints
    query_map = {
        "find_domain_admins": "/queries/domain-admins",
        "kerberoastable_users": "/queries/kerberoastable",
        "high_value_targets": "/queries/high-value-targets",
        "domain_trust_mapping": "/queries/domain-trusts",
        "path_to_domain_admin": "/queries/path-to-domain-admin",
        "unprotected_ous": "/queries/unprotected-ous",
        "adcs_vulnerable_templates": "/queries/vulnerable-certificate-templates"
    }
    
    if query_name not in query_map:
        available_queries = ", ".join(query_map.keys())
        return {
            "error": f"Unknown query: {query_name}",
            "available_queries": available_queries
        }
    
    client = await get_api_client(ctx)
    
    try:
        ctx.info(f"Running analysis query: {query_name}")
        response = await client.get(query_map[query_name])
        response.raise_for_status()
        
        return response.json()
    
    except Exception as e:
        ctx.error(f"Error running analysis query: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
async def get_node_info(node_name: str, ctx: Context) -> Dict[str, Any]:
    """
    Get detailed information about a specific node in BloodHound.
    
    Args:
        node_name: The name of the node (e.g., 'JSMITH@DOMAIN.COM')
    
    Returns:
        Detailed node information including properties and relationships
    """
    client = await get_api_client(ctx)
    
    try:
        ctx.info(f"Getting info for node: {node_name}")
        
        # First get the node itself
        response = await client.get(f"/nodes/{node_name}")
        response.raise_for_status()
        
        node_info = response.json()
        
        # Then get inbound relationships
        inbound_resp = await client.get(f"/nodes/{node_name}/inbound")
        inbound_resp.raise_for_status()
        
        # And outbound relationships
        outbound_resp = await client.get(f"/nodes/{node_name}/outbound")
        outbound_resp.raise_for_status()
        
        return {
            "node": node_info,
            "inbound_relationships": inbound_resp.json(),
            "outbound_relationships": outbound_resp.json()
        }
    
    except Exception as e:
        ctx.error(f"Error getting node info: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
async def execute_cypher_query(params: QueryParams, ctx: Context) -> Dict[str, Any]:
    """
    Execute a custom Cypher query against the BloodHound Neo4j database.
    
    This provides direct access to the graph database using Cypher query language.
    Note that some queries may be restricted for security reasons.
    
    Example queries:
    - Find all Domain Admins:
      MATCH (g:Group) WHERE g.name =~ ".*DOMAIN ADMINS.*" RETURN g
    
    - Find all users with paths to Domain Admin:
      MATCH p=shortestPath((u:User)-[*1..]->(g:Group)) WHERE g.name =~ ".*DOMAIN ADMINS.*" RETURN p
    
    - Find computers where specific user has admin rights:
      MATCH p=(u:User)-[r:AdminTo]->(c:Computer) WHERE u.name='TARGET_USER@DOMAIN.COM' RETURN p
    """
    client = await get_api_client(ctx)
    
    try:
        ctx.info(f"Executing Cypher query: {params.query}")
        response = await client.post("/graphs/cypher", json={"query": params.query})
        response.raise_for_status()
        
        return response.json()
    
    except Exception as e:
        ctx.error(f"Error executing Cypher query: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "note": "Some Cypher queries may be restricted by BloodHound security controls"
        }

@mcp.tool()
async def find_attack_paths(params: AttackPathsParams, ctx: Context) -> Dict[str, Any]:
    """
    Find all attack paths to a specific target node.
    
    You can filter paths by source node and include/exclude specific edge types.
    
    Args:
        target: Target node name or SID
        source: Optional source node (default: any owned nodes)
        include_edges: Optional list of edge types to include in the analysis
        exclude_edges: Optional list of edge types to exclude from the analysis
    
    Returns:
        Dictionary with attack paths and analysis
    """
    client = await get_api_client(ctx)
    
    try:
        ctx.info(f"Finding attack paths to {params.target}")
        
        query_data = {
            "target": params.target
        }
        
        if params.source:
            query_data["source"] = params.source
            
        if params.include_edges:
            query_data["includeEdges"] = params.include_edges
            
        if params.exclude_edges:
            query_data["excludeEdges"] = params.exclude_edges
        
        response = await client.post("/paths/attack", json=query_data)
        response.raise_for_status()
        
        result = response.json()
        
        # Add some analysis to the raw results
        if "paths" in result and len(result["paths"]) > 0:
            severity = "Critical" if len(result["paths"]) > 5 else "High" if len(result["paths"]) > 0 else "Low"
            return {
                "success": True,
                "severity": severity,
                "path_count": len(result["paths"]),
                "paths": result["paths"],
                "analysis": f"Found {len(result['paths'])} attack paths to target. Severity: {severity}"
            }
        else:
            return {
                "success": True,
                "severity": "None",
                "path_count": 0,
                "paths": [],
                "analysis": "No attack paths found to this target"
            }
    
    except Exception as e:
        ctx.error(f"Error finding attack paths: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

@mcp.tool()
async def get_domain_statistics(ctx: Context) -> Dict[str, Any]:
    """
    Get statistics about the domains in the BloodHound database.
    
    Returns information about the number of users, computers, groups,
    and other objects in each domain, as well as relationships between them.
    """
    client = await get_api_client(ctx)
    
    try:
        ctx.info("Getting domain statistics")
        response = await client.get("/domains/stats")
        response.raise_for_status()
        
        return response.json()
    
    except Exception as e:
        ctx.error(f"Error getting domain statistics: {str(e)}")
        return {"error": str(e)}

# Prompts for common security analysis tasks

@mcp.prompt()
def analyze_domain_security() -> str:
    """Create a prompt for comprehensive domain security assessment"""
    return """Please perform a security assessment of the Active Directory environment using BloodHound data.

Steps to include in your analysis:
1. Get domain statistics using the get_domain_statistics tool
2. Identify high-value targets with the run_analysis_query tool using "high_value_targets"
3. Find users who can reach Domain Admin with run_analysis_query using "path_to_domain_admin"
4. Look for kerberoastable users with run_analysis_query using "kerberoastable_users"
5. Check for vulnerable certificate templates with run_analysis_query using "adcs_vulnerable_templates"

Based on this data, please:
- Identify the most critical attack paths
- Suggest prioritized remediation steps
- Explain which security risks should be addressed first

Format your response as a security report with clear sections and actionable recommendations.
"""

@mcp.prompt()
def analyze_attack_path(user: str, target: str = "DOMAIN ADMINS") -> str:
    """Create a prompt to analyze attack paths from a user to a target"""
    return f"""Please analyze the attack paths from {user} to {target}.

First, use the find_shortest_path tool to find if a path exists between {user} and {target}.

If a path exists:
1. Explain each step in the path and what attack techniques could be used
2. Identify critical chokepoints in the path that could be secured
3. Suggest specific remediation steps to block or mitigate this attack path

If no direct path exists, search for potential indirect paths by:
1. Checking if {user} has paths to any high-value targets (use find_attack_paths)
2. Examining if those high-value targets have paths to {target}

Please be detailed in your analysis, focusing on the security implications of each relationship in the path.
"""

@mcp.prompt()
def secure_certificate_services() -> str:
    """Create a prompt for analyzing ADCS security issues"""
    return """Please analyze Active Directory Certificate Services (ADCS) security issues in the environment.

Steps for analysis:
1. Use run_analysis_query with "adcs_vulnerable_templates" to identify vulnerable certificate templates
2. For each vulnerable template, use get_node_info to examine its properties and relationships
3. Check for ESC1 (enrollee supplies subject) and ESC2 (subject alternative name) vulnerabilities
4. Identify any principals that can enroll in vulnerable templates

Based on the findings:
1. Explain the risks associated with each vulnerability
2. Provide specific remediation steps for each vulnerable template
3. Suggest overall improvements to the ADCS security posture

Include information about which attack paths might leverage these ADCS vulnerabilities and how to prioritize fixes.
"""