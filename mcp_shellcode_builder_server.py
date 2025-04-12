import asyncio
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel
import subprocess
import os
import uuid

mcp = FastMCP("shellcode-builder")


def execute(command: str) -> str:
    """Run shell commands and return output or error."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"[ERROR] {e.stderr.strip()}"


class ShellcodeSource(BaseModel):
    code: str
    language: str = "c"  # or cpp


@mcp.tool()
async def save_source_and_compile(req: ShellcodeSource) -> str:
    """
    Save source code to file and compile it using gcc or g++.

    :param code: C or C++ source code as string
    :type code: str
    :param language: Programming language ('c' or 'cpp')
    :type language: str
    :return: Compilation result or error
    :rtype: str
    """
    uid = str(uuid.uuid4())[:8]
    ext = ".cpp" if req.language == "cpp" else ".c"
    filename = f"/tmp/payload_{uid}{ext}"
    binary = f"/tmp/shellcode_{uid}"

    # Write source to file
    with open(filename, "w") as f:
        f.write(req.code)

    # Compile
    compiler = "g++" if req.language == "cpp" else "gcc"
    cmd = f"{compiler} -fPIC -O2 -o {binary} {filename}"

    compile_output = execute(cmd)
    if "[ERROR]" in compile_output:
        return compile_output

    return f"Compiled successfully: {binary}"


class BinaryPath(BaseModel):
    path: str


@mcp.tool()
async def extract_shellcode(req: BinaryPath) -> str:
    """
    Extract shellcode bytes from compiled binary using objdump.

    :param path: Path to compiled binary
    :type path: str
    :return: Shellcode in \\x format
    :rtype: str
    """
    cmd = f"objdump -d {req.path} | grep '^ ' | cut -f2 | tr -d '\\n' | sed 's/\\(..\\)/\\\\x\\1/g'"
    return execute(cmd)


if __name__ == "__main__":
    mcp.run()

