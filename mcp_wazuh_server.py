# mcp_wazuh_server.py
import asyncio
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel
import subprocess
import json

mcp = FastMCP("wazuh-analyst")


def execute(command: str) -> str:
    """Run shell command and return output or error."""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"[ERROR] {e.stderr.strip()}"


@mcp.tool()
async def tail_wazuh_alerts(lines: int = 20) -> str:
    """
    Tail the last N lines of Wazuh alerts JSON file.

    :param lines: Number of lines to tail (default: 20)
    :type lines: int
    :return: Last alerts in raw JSON format
    :rtype: str
    """
    cmd = f"tail -n {lines} /var/ossec/logs/alerts/alerts.json"
    return execute(cmd)


@mcp.tool()
async def count_high_severity_alerts() -> str:
    """
    Count the number of high severity alerts in Wazuh.

    :return: Count of high severity events
    :rtype: str
    """
    try:
        with open("/var/ossec/logs/alerts/alerts.json", "r") as f:
            lines = f.readlines()

        high = [json.loads(line) for line in lines if '"level":' in line and '"level": 10' in line]
        return f"High severity alerts: {len(high)}"
    except Exception as e:
        return f"[ERROR] {str(e)}"


class IPInput(BaseModel):
    ip: str


@mcp.tool()
async def block_ip_with_firewall(req: IPInput) -> str:
    """
    Block an IP address using iptables.

    :param ip: IP address to block
    :type ip: str
    :return: Result of firewall command
    :rtype: str
    """
    return execute(f"iptables -A INPUT -s {req.ip} -j DROP")


@mcp.tool()
async def analyze_ruleset() -> str:
    """
    List custom Wazuh rule files.

    :return: List of rule files in Wazuh ruleset
    :rtype: str
    """
    return execute("ls /var/ossec/ruleset/rules/")


if __name__ == "__main__":
    asyncio.run(mcp.run_stdio())
