#!/usr/bin/env python3
"""
CORS Misconfiguration Tester via Burp Suite MCP
Bypasses WAF (Alibaba Cloud, Cloudflare) by sending requests through Burp.

Usage:
  python3 scripts/burp_cors_test.py <target_host> [--port 443] [--endpoints /,/api,/api/v1]

Requirements:
  - Burp Suite running with MCP extension on port 9876
  - mcp Python package installed (pip install mcp)
"""
import asyncio
import argparse
import sys

DEFAULT_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://TARGET.evil.com",
    "https://test.TARGET",
]

DEFAULT_ENDPOINTS = ["/", "/api", "/api/v1", "/api/v2", "/api/user", "/api/profile", "/api/account", "/api/login"]


async def test_cors(host: str, port: int = 443, origins: list = None, endpoints: list = None):
    from mcp.client.sse import sse_client
    from mcp import ClientSession

    if origins is None:
        origins = [o.replace("TARGET", host) for o in DEFAULT_ORIGINS]
    if endpoints is None:
        endpoints = DEFAULT_ENDPOINTS

    results = []

    async with sse_client("http://127.0.0.1:9876/") as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            print(f"{'Endpoint':<25} | {'Origin':<35} | {'Status':<6} | {'ACAO':<35} | {'ACAC':<6}")
            print("-" * 125)

            for endpoint in endpoints:
                for origin in origins:
                    req = f"GET {endpoint} HTTP/1.1\r\nHost: {host}\r\nOrigin: {origin}\r\nAccept: */*\r\n\r\n"
                    try:
                        result = await session.call_tool("send_http1_request", {
                            "content": req,
                            "targetHostname": host,
                            "targetPort": port,
                            "usesHttps": port == 443
                        })
                        for item in result.content:
                            if hasattr(item, 'text'):
                                lines = item.text.replace('\\r\\n', '\r\n').split('\r\n')

                                status = "N/A"
                                for line in lines:
                                    if line.startswith('HTTP/'):
                                        parts = line.split(' ')
                                        if len(parts) > 1:
                                            status = parts[1]
                                        break

                                acao = "N/A"
                                acac = "N/A"
                                for line in lines:
                                    if 'access-control-allow-origin:' in line.lower():
                                        acao = line.split(':', 1)[1].strip()
                                    if 'access-control-allow-credentials:' in line.lower():
                                        acac = line.split(':', 1)[1].strip()

                                vuln = "VULN" if acao == origin and acac.lower() == "true" else "SAFE"
                                print(f"{endpoint:<25} | {origin:<35} | {status:<6} | {acao:<35} | {acac:<6}")

                                results.append({
                                    "endpoint": endpoint,
                                    "origin": origin,
                                    "status": status,
                                    "acao": acao,
                                    "acac": acac,
                                    "vulnerable": vuln == "VULN"
                                })
                    except Exception as e:
                        print(f"{endpoint:<25} | {origin:<35} | ERROR  | {str(e)[:35]} |")

    # Summary
    vuln_count = sum(1 for r in results if r["vulnerable"])
    print(f"\n{'=' * 125}")
    print(f"Total tests: {len(results)} | Vulnerable: {vuln_count} | Safe: {len(results) - vuln_count}")

    if vuln_count > 0:
        print(f"\nVULNERABLE ENDPOINTS:")
        for r in results:
            if r["vulnerable"]:
                print(f"  {r['endpoint']} | Origin: {r['origin']} | ACAO: {r['acao']} | ACAC: {r['acac']}")

    return results


def main():
    parser = argparse.ArgumentParser(description="CORS Tester via Burp MCP")
    parser.add_argument("host", help="Target hostname (e.g., app.target.com)")
    parser.add_argument("--port", type=int, default=443, help="Target port (default: 443)")
    parser.add_argument("--origins", nargs="+", help="Custom origins to test")
    parser.add_argument("--endpoints", nargs="+", help="Custom endpoints to test")
    args = parser.parse_args()

    asyncio.run(test_cors(args.host, args.port, args.origins, args.endpoints))


if __name__ == "__main__":
    main()
