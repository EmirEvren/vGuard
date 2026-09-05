"""OpenAPI Specification and Swagger UI documentation endpoints."""
from flask import Blueprint, jsonify, render_template_string

docs_bp = Blueprint("docs", __name__)

OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {
        "title": "vGuard SOC & IDS/IPS API",
        "description": "RESTful and Real-Time Event Streaming API for vGuard Intrusion Detection & Prevention System.",
        "version": "2.0.0",
    },
    "servers": [
        {"url": "/", "description": "Current Environment"}
    ],
    "paths": {
        "/api/auth/login": {
            "post": {
                "summary": "Authenticate user session",
                "tags": ["Authentication"],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "username": {"type": "string", "example": "admin"},
                                    "password": {"type": "string", "example": "Vg!2026-Secure#A1"}
                                },
                                "required": ["username", "password"]
                            }
                        }
                    }
                },
                "responses": {
                    "200": {"description": "Authenticated successfully"},
                    "401": {"description": "Invalid credentials or account locked"},
                    "429": {"description": "Rate limit exceeded"}
                }
            }
        },
        "/api/auth/logout": {
            "post": {
                "summary": "Log out current user",
                "tags": ["Authentication"],
                "responses": {
                    "200": {"description": "Logged out"}
                }
            }
        },
        "/api/me": {
            "get": {
                "summary": "Get authenticated user profile",
                "tags": ["Authentication"],
                "responses": {
                    "200": {"description": "User details"},
                    "401": {"description": "Unauthorized"}
                }
            }
        },
        "/api/status": {
            "get": {
                "summary": "Get engine heartbeat and telemetry status",
                "tags": ["Monitoring"],
                "responses": {
                    "200": {"description": "Engine and system status metrics"}
                }
            }
        },
        "/api/logs": {
            "get": {
                "summary": "Query security event logs",
                "tags": ["Events"],
                "parameters": [
                    {"name": "severity", "in": "query", "schema": {"type": "string", "enum": ["low", "medium", "high", "critical"]}},
                    {"name": "action", "in": "query", "schema": {"type": "string", "enum": ["ACCEPT", "DROP", "BAN", "ALERT"]}},
                    {"name": "resolved", "in": "query", "schema": {"type": "string", "enum": ["0", "1"]}},
                    {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 500}},
                    {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}}
                ],
                "responses": {
                    "200": {"description": "List of IDS/IPS events"}
                }
            }
        },
        "/api/logs/stream": {
            "get": {
                "summary": "Real-time Server-Sent Events (SSE) log stream",
                "tags": ["Events"],
                "responses": {
                    "200": {"description": "text/event-stream real-time connection"}
                }
            }
        },
        "/api/logs/export.csv": {
            "get": {
                "summary": "Export security events to CSV file",
                "tags": ["Events"],
                "responses": {
                    "200": {"description": "CSV stream attachment"}
                }
            }
        },
        "/api/logs/export.cef": {
            "get": {
                "summary": "Export security events to ArcSight CEF format for SIEM integration",
                "tags": ["Events"],
                "responses": {
                    "200": {"description": "CEF plain text stream"}
                }
            }
        },
        "/api/logs/export.syslog": {
            "get": {
                "summary": "Export security events to RFC 5424 Syslog format",
                "tags": ["Events"],
                "responses": {
                    "200": {"description": "Syslog plain text stream"}
                }
            }
        },
        "/api/health": {
            "get": {
                "summary": "System and database health telemetry probe",
                "tags": ["Monitoring"],
                "responses": {
                    "200": {"description": "System health metrics"}
                }
            }
        },
        "/api/risks": {
            "get": {
                "summary": "List tracked IP threat risk scores",
                "tags": ["Threat Intelligence"],
                "responses": {
                    "200": {"description": "Array of IP risk records"}
                }
            }
        },
        "/api/risks/{ip}": {
            "get": {
                "summary": "Get specific IP threat profile and score",
                "tags": ["Threat Intelligence"],
                "parameters": [
                    {"name": "ip", "in": "path", "required": True, "schema": {"type": "string"}}
                ],
                "responses": {
                    "200": {"description": "IP risk breakdown"}
                }
            }
        },
        "/api/analyze": {
            "post": {
                "summary": "Perform AI threat remediation analysis on an alert",
                "tags": ["Threat Intelligence"],
                "responses": {
                    "200": {"description": "Structured AI remediation report"}
                }
            }
        },
        "/api/simulate": {
            "post": {
                "summary": "Execute safe attack probe simulation",
                "tags": ["Simulator"],
                "responses": {
                    "200": {"description": "Simulation result"}
                }
            }
        },
        "/api/bans": {
            "get": {
                "summary": "List all active and historical IP bans",
                "tags": ["Bans"],
                "responses": {
                    "200": {"description": "Array of IP ban records"}
                }
            },
            "post": {
                "summary": "Create a new IP ban",
                "tags": ["Bans"],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "ip": {"type": "string", "example": "198.51.100.25"},
                                    "reason": {"type": "string", "example": "SQL Injection attempt"},
                                    "duration": {"type": "integer", "default": 3600}
                                },
                                "required": ["ip"]
                            }
                        }
                    }
                },
                "responses": {
                    "201": {"description": "IP banned successfully"},
                    "400": {"description": "Invalid input"}
                }
            }
        },
        "/api/rules": {
            "get": {
                "summary": "Retrieve threat detection signatures",
                "tags": ["Rules"],
                "responses": {
                    "200": {"description": "Rules grouped by category"}
                }
            },
            "post": {
                "summary": "Update or save detection signatures",
                "tags": ["Rules"],
                "responses": {
                    "200": {"description": "Rules updated"}
                }
            }
        },
        "/api/users": {
            "get": {
                "summary": "List all dashboard users (Admin only)",
                "tags": ["Users"],
                "responses": {
                    "200": {"description": "User accounts list"}
                }
            }
        },
        "/api/mitigation/status": {
            "get": {
                "summary": "Get Active Defense & Threat Mitigation posture and subsystem stats",
                "tags": ["Active Defense"],
                "responses": {
                    "200": {"description": "Active Defense telemetry and statistics"}
                }
            }
        },
        "/api/mitigation/evaluate": {
            "post": {
                "summary": "Evaluate candidate threat and trigger active counter-measures",
                "tags": ["Active Defense"],
                "responses": {
                    "200": {"description": "Mitigation result and actions taken"}
                }
            }
        },
        "/api/mitigation/honeytokens": {
            "get": {
                "summary": "List active canary honeytokens and breach events",
                "tags": ["Active Defense"],
                "responses": {
                    "200": {"description": "Honeytoken assets and trip statistics"}
                }
            }
        }
    }
}

SWAGGER_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>vGuard API Documentation</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css" />
  <style>
    body { margin: 0; background: #0b132b; color: #fff; }
    .swagger-ui { filter: invert(88%) hue-rotate(180deg); }
    .swagger-ui .topbar { display: none; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => {
      SwaggerUIBundle({
        url: '/api/spec.json',
        dom_id: '#swagger-ui',
        presets: [SwaggerUIBundle.presets.apis],
        layout: "BaseLayout"
      });
    };
  </script>
</body>
</html>
"""


@docs_bp.route("/api/spec.json", methods=["GET"])
def get_spec():
    """Return OpenAPI 3.0 specification."""
    return jsonify(OPENAPI_SPEC), 200


@docs_bp.route("/docs", methods=["GET"])
def get_docs():
    """Render Swagger UI documentation interface."""
    return render_template_string(SWAGGER_HTML), 200
