"""Aegis CLI entry point."""

import sys
import argparse
import getpass
import os
from datetime import datetime, timezone

from aegis import __version__
from aegis.exceptions import ErrorCode, AegisError
from aegis.settings import _default_data_dir, is_dev_mode
from aegis.signal_handling import install_signal_handlers
from aegis.redact import redact_utr


def main() -> None:
    from aegis.auth import Authenticator

    install_signal_handlers()

    parser = argparse.ArgumentParser(
        prog="aegis",
        description="A security gateway for AI and software agents",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--data-dir",
        default=None,
        help="Aegis data directory (default: ~/.aegis on Linux, "
        "~/Library/Application Support/Aegis on macOS, "
        "%%APPDATA%%/Aegis on Windows)",
    )

    sub = parser.add_subparsers(dest="command")

    # --- auth ---
    auth_p = sub.add_parser("auth", help="Authentication and authorization")
    auth_sub = auth_p.add_subparsers(dest="auth_command")
    auth_sub.add_parser("whoami", help="Show the current authenticated user")
    auth_sub.add_parser("permissions", help="Show your permissions")
    mfa_p = auth_sub.add_parser("mfa", help="Manage multi-factor authentication")
    mfa_sub = mfa_p.add_subparsers(dest="mfa_command")
    mfa_sub.add_parser("status", help="Show MFA status")
    mfa_enable_p = mfa_sub.add_parser("enable", help="Generate a new TOTP secret and enable MFA")
    mfa_enable_p.add_argument("--username", default=None, help="Username (for provisioning URI)")
    mfa_confirm_p = mfa_sub.add_parser("confirm", help="Confirm MFA setup with a TOTP code")
    mfa_confirm_p.add_argument("code", help="TOTP code from your authenticator app")
    mfa_sub.add_parser("disable", help="Disable MFA")
    mfa_sub.add_parser("regenerate-recovery-codes", help="Generate new recovery codes")

    # --- user ---
    user_p = sub.add_parser("user", help="Manage user accounts")
    user_sub = user_p.add_subparsers(dest="user_command")
    user_create_p = user_sub.add_parser("create", help="Create a new user")
    user_create_p.add_argument("username", help="Username (3-32 chars, letters/digits/_-)")
    user_role_p = user_sub.add_parser("role", help="Manage user roles")
    user_role_sub = user_role_p.add_subparsers(dest="user_role_command")
    user_role_set_p = user_role_sub.add_parser("set", help="Set a user's role")
    user_role_set_p.add_argument("username", help="Username")
    user_role_set_p.add_argument("role", help="Role name (USER, PAYMENT_VERIFIER, ADMIN)")

    # --- login ---
    login_p = sub.add_parser("login", help="Log in to Aegis")
    login_p.add_argument("username", help="Username")

    # --- logout ---
    sub.add_parser("logout", help="Log out of Aegis")

    # --- whoami ---
    sub.add_parser("whoami", help="Show the current authenticated user")

    # --- agent ---
    agent_p = sub.add_parser("agent", help="Manage AI agents")
    agent_sub = agent_p.add_subparsers(dest="agent_command")
    agent_create_p = agent_sub.add_parser("create", help="Register a new agent")
    agent_create_p.add_argument("name", help="Agent name (1-64 chars, letters/digits/._-)")
    agent_sub.add_parser("list", help="List your agents")
    agent_show_p = agent_sub.add_parser("show", help="Show agent details")
    agent_show_p.add_argument("agent_id", help="Agent UUID")
    agent_revoke_p = agent_sub.add_parser("revoke", help="Revoke an agent")
    agent_revoke_p.add_argument("agent_id", help="Agent UUID")

    # --- policy ---
    policy_p = sub.add_parser("policy", help="Manage security policies")
    policy_sub = policy_p.add_subparsers(dest="policy_command")
    policy_apply_p = policy_sub.add_parser("apply", help="Load a policy from a YAML file")
    policy_apply_p.add_argument("file", help="Path to policy YAML file")
    policy_sub.add_parser("list", help="List your policies")
    policy_show_p = policy_sub.add_parser("show", help="Show policy details")
    policy_show_p.add_argument("policy_id", help="Policy ID")

    # --- audit ---
    audit_p = sub.add_parser("audit", help="View and verify audit logs")
    audit_sub = audit_p.add_subparsers(dest="audit_command")
    audit_sub.add_parser("list", help="List your audit events")
    audit_show_p = audit_sub.add_parser("show", help="Show an audit event")
    audit_show_p.add_argument("event_id", help="Decision event UUID")
    audit_sub.add_parser("verify", help="Verify integrity of the audit chain")

    # --- action ---
    action_p = sub.add_parser("action", help="Evaluate an agent action")
    action_sub = action_p.add_subparsers(dest="action_command")
    action_eval_p = action_sub.add_parser("evaluate", help="Evaluate an action against policy")
    action_eval_p.add_argument("agent_id", help="Agent UUID")
    action_eval_p.add_argument("policy_id", help="Policy ID")
    action_eval_p.add_argument("action_file", help="Path to action JSON file")

    # --- process ---
    proc_p = sub.add_parser("process", help="Controlled process execution")
    proc_sub = proc_p.add_subparsers(dest="process_command")
    proc_run_p = proc_sub.add_parser("run", help="Run an allowlisted executable")
    proc_run_p.add_argument("agent_id", help="Agent UUID")
    proc_run_p.add_argument("policy_id", help="Policy ID")
    proc_run_p.add_argument("executable_name", help="Allowlisted executable name")
    proc_run_p.add_argument(
        "process_args", nargs=argparse.REMAINDER,
        help="Arguments passed to the executable (use -- to separate)",
    )
    proc_run_p.add_argument(
        "--timeout", type=int, default=30,
        help="Execution timeout in seconds (default: 30)",
    )
    proc_run_p.add_argument(
        "--output-limit", type=int, default=1_048_576,
        help="Max stdout/stderr bytes per stream (default: 1 MiB)",
    )
    proc_run_p.add_argument(
        "--cwd", default=None,
        help="Working directory for the process (default: current dir)",
    )

    proc_allow_p = proc_sub.add_parser("allowlist", help="Manage executable allowlist")
    proc_allow_sub = proc_allow_p.add_subparsers(dest="allowlist_command")
    proc_allow_add_p = proc_allow_sub.add_parser("add", help="Add an executable to the allowlist")
    proc_allow_add_p.add_argument("name", help="Logical name for the executable")
    proc_allow_add_p.add_argument("path", help="Path to the executable")
    proc_allow_sub.add_parser("list", help="List allowlisted executables")

    # --- net ---
    net_p = sub.add_parser("net", help="Controlled network operations")
    net_sub = net_p.add_subparsers(dest="net_command")
    net_req_p = net_sub.add_parser("request", help="Perform a controlled HTTP request")
    net_req_p.add_argument("agent_id", help="Agent UUID")
    net_req_p.add_argument("policy_id", help="Policy ID")
    net_req_p.add_argument("url", help="Destination URL (http or https only)")
    net_req_p.add_argument("--method", default="GET", choices=["GET", "HEAD"],
                           help="HTTP method (default: GET)")
    net_req_p.add_argument("--timeout", type=int, default=30,
                           help="Request timeout in seconds (default: 30)")
    net_req_p.add_argument("--max-size", type=int, default=10_485_760,
                           help="Max response body bytes (default: 10 MiB)")

    net_allow_p = net_sub.add_parser("allowlist", help="Manage network destination allowlist")
    net_allow_sub = net_allow_p.add_subparsers(dest="net_allow_command")
    net_allow_add_p = net_allow_sub.add_parser("add", help="Add a network destination")
    net_allow_add_p.add_argument("name", help="Logical name for the destination")
    net_allow_add_p.add_argument("--scheme", required=True, choices=["http", "https"],
                                 help="URL scheme")
    net_allow_add_p.add_argument("--hostname", required=True,
                                 help="Fully qualified hostname")
    net_allow_add_p.add_argument("--port", type=int, default=None,
                                 help="Port number (default: 80 or 443 based on scheme)")
    net_allow_add_p.add_argument("--path-prefix", default="/",
                                 help="Path prefix (default: /)")
    net_allow_sub.add_parser("list", help="List allowed network destinations")

    # --- plan ---
    plan_p = sub.add_parser("plan", help="View subscription plans")
    plan_sub = plan_p.add_subparsers(dest="plan_command")
    plan_sub.add_parser("list", help="List available plans")

    # --- subscription ---
    sub_p = sub.add_parser("subscription", help="Manage your subscription")
    sub_sub = sub_p.add_subparsers(dest="sub_command")
    sub_sub.add_parser("status", help="Show your subscription status")
    sub_activate_p = sub_sub.add_parser("activate", help="Activate a subscription plan")
    sub_activate_p.add_argument("plan_id", help="Plan ID (free, pro, enterprise)")

    # --- entitlement ---
    ent_p = sub.add_parser("entitlement", help="View your entitlements")
    ent_sub = ent_p.add_subparsers(dest="ent_command")
    ent_sub.add_parser("list", help="List your entitlements")

    # --- ai ---
    ai_p = sub.add_parser("ai", help="AI Security Copilot (advisory only)")
    ai_sub = ai_p.add_subparsers(dest="ai_command")
    ai_explain_p = ai_sub.add_parser("explain", help="Explain a decision")
    ai_explain_p.add_argument("decision_id", help="Decision UUID")
    ai_sub.add_parser("audit-summary", help="Summarise audit events")
    ai_review_p = ai_sub.add_parser("policy-review", help="Analyse a policy for risks")
    ai_review_p.add_argument("policy_id", help="Policy ID")
    ai_draft_p = ai_sub.add_parser("policy-draft", help="Draft a policy from natural language")
    ai_draft_p.add_argument("description", help="Natural-language policy description")

    # --- payment ---
    pay_p = sub.add_parser("payment", help="Payment and verification")
    pay_sub = pay_p.add_subparsers(dest="pay_command")
    pay_submit_p = pay_sub.add_parser("submit", help="Submit a payment for verification")
    pay_submit_p.add_argument("--plan", required=True, help="Plan ID (pro, enterprise)")
    pay_submit_p.add_argument("--utr", required=True, help="UPI Transaction Reference")
    pay_status_p = pay_sub.add_parser("status", help="Show payment status")
    pay_status_p.add_argument("payment_id", help="Payment UUID")
    pay_sub.add_parser("list", help="List your payments")

    # --- admin ---
    admin_p = sub.add_parser("admin", help="Administrative operations")
    admin_sub = admin_p.add_subparsers(dest="admin_command")
    admin_pay_p = admin_sub.add_parser("payment", help="Payment administration")
    admin_pay_sub = admin_pay_p.add_subparsers(dest="admin_payment_command")
    admin_pay_verify_p = admin_pay_sub.add_parser("verify", help="Verify a PENDING payment")
    admin_pay_verify_p.add_argument("payment_id", help="Payment UUID")
    admin_pay_reject_p = admin_pay_sub.add_parser("reject", help="Reject a PENDING payment")
    admin_pay_reject_p.add_argument("payment_id", help="Payment UUID")
    admin_pay_reject_p.add_argument("--reason", required=True, help="Rejection reason")

    # --- db ---
    db_p = sub.add_parser("db", help="Database operations")
    db_sub = db_p.add_subparsers(dest="db_command")
    db_migrate_p = db_sub.add_parser("migrate", help="Migrate NDJSON data to database")
    db_migrate_p.add_argument(
        "--rebuild", action="store_true",
        help="Drop and recreate all tables before migration",
    )

    # --- serve ---
    serve_p = sub.add_parser("serve", help="Start the API server")
    serve_p.add_argument(
        "--host", default="127.0.0.1",
        help="Bind address (default: 127.0.0.1)",
    )
    serve_p.add_argument(
        "--port", type=int, default=8000,
        help="Bind port (default: 8000)",
    )
    serve_p.add_argument(
        "--cors-origins", default=None,
        help="Comma-separated CORS origins (default: AEGIS_CORS_ORIGINS env)",
    )
    serve_p.add_argument(
        "--reload", action="store_true",
        help="Enable auto-reload (development only)",
    )

    # --- backup ---
    backup_p = sub.add_parser("backup", help="Backup and restore data")
    backup_sub = backup_p.add_subparsers(dest="backup_command")
    backup_sub.add_parser("create", help="Create a timestamped backup of the data directory")
    backup_sub.add_parser("list", help="List available backups")
    backup_restore_p = backup_sub.add_parser("restore", help="Restore data from a backup")
    backup_restore_p.add_argument("backup_path", help="Path to the backup zip file")

    # --- fs ---
    fs_p = sub.add_parser("fs", help="Controlled filesystem operations")
    fs_sub = fs_p.add_subparsers(dest="fs_command")
    fs_read_p = fs_sub.add_parser("read", help="Read a file within the allowed scope")
    fs_read_p.add_argument("agent_id", help="Agent UUID")
    fs_read_p.add_argument("policy_id", help="Policy ID")
    fs_read_p.add_argument("path", help="Path to the file to read")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(ErrorCode.SUCCESS.value)

    args = parser.parse_args()
    data_dir = args.data_dir if args.data_dir else _default_data_dir()
    auth = Authenticator(data_dir)

    try:
        if args.command == "user":
            if args.user_command == "create":
                _handle_user_create(auth, args)
            elif args.user_command == "role":
                _handle_user_role_set(auth, args, data_dir)
            else:
                user_p.print_help()
                sys.exit(ErrorCode.INVALID_INPUT.value)

        elif args.command == "login":
            _handle_login(auth, args)

        elif args.command == "logout":
            _handle_logout(auth)

        elif args.command == "whoami":
            _handle_whoami(auth)

        elif args.command == "agent":
            _handle_agent(auth, args, data_dir)

        elif args.command == "policy":
            _handle_policy(auth, args, data_dir)

        elif args.command == "audit":
            _handle_audit(auth, args, data_dir)

        elif args.command == "action":
            _handle_action(auth, args, data_dir)

        elif args.command == "process":
            _handle_process(auth, args, data_dir)

        elif args.command == "plan":
            _handle_plan(auth, args, data_dir)

        elif args.command == "subscription":
            _handle_subscription(auth, args, data_dir)

        elif args.command == "entitlement":
            _handle_entitlement(auth, args, data_dir)

        elif args.command == "net":
            _handle_net(auth, args, data_dir)

        elif args.command == "ai":
            _handle_ai(auth, args, data_dir)

        elif args.command == "payment":
            _handle_payment(auth, args, data_dir)

        elif args.command == "auth":
            _handle_auth(auth, args, data_dir)

        elif args.command == "admin":
            _handle_admin(auth, args, data_dir)

        elif args.command == "db":
            _handle_db(args, data_dir)

        elif args.command == "serve":
            _handle_serve(args)

        elif args.command == "backup":
            _handle_backup(args, data_dir)

        elif args.command == "fs":
            _handle_fs(auth, args, data_dir)

        else:
            parser.print_help()
            sys.exit(ErrorCode.INVALID_INPUT.value)

    except ValueError as e:
        AegisError(str(e), ErrorCode.INVALID_INPUT).exit()
    except Exception as e:
        AegisError(str(e)).exit()


def _handle_user_create(auth: "Authenticator", args: argparse.Namespace) -> None:
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        AegisError("Passwords do not match", ErrorCode.PASSWORDS_DO_NOT_MATCH).exit()
    user = auth.register(args.username, password)
    print(f"User {user.username!r} created successfully (id={user.id})")


def _handle_user_role_set(auth: "Authenticator", args: argparse.Namespace, data_dir: str) -> None:
    from aegis.rbac import AuthorizationService, AuthorizationError
    from aegis.rbac import Role

    user = _require_auth(auth)

    # Authorization check
    authz = AuthorizationService(data_dir)
    try:
        authz.require(user.id, "user.manage")
    except AuthorizationError:
        AegisError("You do not have permission to manage user roles.", ErrorCode.PERMISSION_DENIED).exit()

    # Find target user
    target = auth.get_user_by_username(args.username)
    if target is None:
        AegisError(f"User {args.username!r} not found", ErrorCode.NOT_FOUND).exit()

    # Prevent self-escalation
    if target.id == user.id:
        AegisError("You cannot change your own role.", ErrorCode.SELF_ROLE_CHANGE).exit()

    role = args.role.upper()
    valid_roles = {r.value for r in Role}
    if role not in valid_roles:
        AegisError(f"Invalid role {role!r}. Valid roles: {sorted(valid_roles)}", ErrorCode.INVALID_ROLE).exit()

    # Enforce admin MFA policy
    try:
        AuthorizationService.require_mfa_for_admin_assignment(target, role)
    except AuthorizationError as e:
        AegisError(str(e), ErrorCode.PERMISSION_DENIED).exit()

    updated = auth.set_user_role(target.id, role)
    authz.audit_privileged_action(
        actor_id=user.id,
        operation="user.role.set",
        target_id=target.id,
        result="SUCCESS",
        target_user_id=target.id,
        reason=f"Role changed from {target.role} to {role}",
    )
    print(f"User {updated.username!r} role set to {role}")


def _handle_login(auth: "Authenticator", args: argparse.Namespace) -> None:
    password = getpass.getpass("Password: ")
    session, raw_token, pending_mfa_token = auth.login_mfa_aware(args.username, password)
    if pending_mfa_token:
        auth.save_pending_mfa_token(pending_mfa_token)
        print(f"Password correct. MFA is required for {args.username!r}.")
        totp_code = getpass.getpass("TOTP code (or 'recovery' to use a recovery code): ")
        try:
            if totp_code.strip().lower() == "recovery":
                recovery_code = getpass.getpass("Recovery code: ")
                session, raw_token = auth.verify_recovery_and_create_session(pending_mfa_token, recovery_code)
            else:
                session, raw_token = auth.verify_totp_and_create_session(pending_mfa_token, totp_code)
        except ValueError as e:
            auth.clear_pending_mfa_token()
            AegisError(str(e), ErrorCode.AUTH_FAILED).exit()
        auth.clear_pending_mfa_token()
        auth.save_session_token(raw_token)
        print(f"Logged in as {args.username!r}")
        return
    auth.save_session_token(raw_token)
    print(f"Logged in as {args.username!r}")


def _handle_logout(auth: "Authenticator") -> None:
    raw_token = auth.load_session_token()
    if raw_token is None:
        AegisError("Not logged in", ErrorCode.NOT_LOGGED_IN).exit()
    auth.logout(raw_token)
    auth.clear_session_token()
    print("Logged out")


def _handle_whoami(auth: "Authenticator") -> None:
    raw_token = auth.load_session_token()
    if raw_token is None:
        AegisError("Not logged in", ErrorCode.NOT_LOGGED_IN).exit()
    user = auth.validate_session(raw_token)
    if user is None:
        auth.clear_session_token()
        AegisError("Session expired or invalid", ErrorCode.SESSION_EXPIRED).exit()
    print(f"Authenticated as {user.username!r} (id={user.id})")


# ---------------------------------------------------------------------------
# Agent handlers
# ---------------------------------------------------------------------------


def _require_auth(auth: "Authenticator") -> "User":
    """Return the authenticated User or exit."""
    from aegis.auth import User
    raw_token = auth.load_session_token()
    if raw_token is None:
        AegisError("Not logged in. Run 'aegis login' first.", ErrorCode.NOT_LOGGED_IN).exit()
    user = auth.validate_session(raw_token)
    if user is None:
        auth.clear_session_token()
        AegisError("Session expired or invalid. Run 'aegis login' again.", ErrorCode.SESSION_EXPIRED).exit()
    return user


def _handle_agent(auth: "Authenticator", args: argparse.Namespace, data_dir: str) -> None:
    from aegis.registry import AgentRegistry

    registry = AgentRegistry(data_dir)

    if args.agent_command == "create":
        user = _require_auth(auth)
        from aegis.entitlement import EntitlementService
        svc = EntitlementService(data_dir)
        max_agents = svc.limit(user.id, "agents.max")
        existing = registry.list_for_user(user.id)
        active_count = sum(1 for a in existing if not a.revoked)
        if active_count >= max_agents:
            AegisError(f"Agent limit ({max_agents}) reached. Upgrade your plan.", ErrorCode.LIMIT_REACHED).exit()
        agent = registry.create(user.id, args.name)
        print(f"Agent {agent.name!r} created (id={agent.id})")

    elif args.agent_command == "list":
        user = _require_auth(auth)
        agents = registry.list_for_user(user.id)
        if not agents:
            print("No agents registered.")
            return
        for a in agents:
            status = "revoked" if a.revoked else "active"
            print(f"  {a.id}  {a.name:<30} {a.created_at.date()}  {status}")

    elif args.agent_command == "show":
        user = _require_auth(auth)
        agent = registry.get_for_user(args.agent_id, user.id)
        print(f"ID:        {agent.id}")
        print(f"Name:      {agent.name}")
        print(f"Created:   {agent.created_at.isoformat()}")
        print(f"Status:    {'revoked' if agent.revoked else 'active'}")
        if agent.revoked_at:
            print(f"Revoked:   {agent.revoked_at.isoformat()}")

    elif args.agent_command == "revoke":
        user = _require_auth(auth)
        agent = registry.revoke(args.agent_id, user.id)
        print(f"Agent {agent.name!r} revoked.")

    else:
        AegisError("Usage: aegis agent create|list|show|revoke (see 'aegis agent --help')", ErrorCode.INVALID_INPUT).exit()


# ---------------------------------------------------------------------------
# Policy handlers
# ---------------------------------------------------------------------------


def _handle_policy(auth: "Authenticator", args: argparse.Namespace, data_dir: str) -> None:
    from aegis.policy import PolicyStore, load_policy_file

    store = PolicyStore(data_dir)

    if args.policy_command == "apply":
        user = _require_auth(auth)
        from aegis.entitlement import EntitlementService
        svc = EntitlementService(data_dir)
        max_policies = svc.limit(user.id, "policies.max")
        existing = store.list_for_user(user.id)
        if len(existing) >= max_policies:
            AegisError(f"Policy limit ({max_policies}) reached. Upgrade your plan.", ErrorCode.LIMIT_REACHED).exit()
        policy = load_policy_file(args.file, user.id)
        store.save(policy)
        print(f"Policy {policy.name!r} applied (id={policy.id}, {len(policy.rules)} rule(s))")

    elif args.policy_command == "list":
        user = _require_auth(auth)
        policies = store.list_for_user(user.id)
        if not policies:
            print("No policies defined.")
            return
        for p in policies:
            status = "enabled" if p.enabled else "disabled"
            print(f"  {p.id}  {p.name:<40} pri={p.priority}  {status}")

    elif args.policy_command == "show":
        user = _require_auth(auth)
        policy = store.get_by_id(args.policy_id, user.id)
        print(f"ID:         {policy.id}")
        print(f"Name:       {policy.name}")
        print(f"Priority:   {policy.priority}")
        print(f"Enabled:    {policy.enabled}")
        print(f"Created:    {policy.created_at.isoformat()}")
        print(f"Rules:      {len(policy.rules)}")
        for i, r in enumerate(policy.rules, 1):
            comment = f"  # {r.comment}" if r.comment else ""
            print(f"  {i}. [{r.effect.value}] {r.match}{comment}")

    else:
        AegisError("Usage: aegis policy apply|list|show (see 'aegis policy --help')", ErrorCode.INVALID_INPUT).exit()


# ---------------------------------------------------------------------------
# Audit handlers
# ---------------------------------------------------------------------------


def _handle_audit(auth: "Authenticator", args: argparse.Namespace, data_dir: str) -> None:
    from aegis.audit import AuditStore

    store = AuditStore(data_dir)

    if args.audit_command == "list":
        user = _require_auth(auth)
        events = store.list(user.id)
        if not events:
            print("No audit events found.")
            return
        _print_audit_events(events)

    elif args.audit_command == "show":
        user = _require_auth(auth)
        event = store.get(args.event_id, user.id)
        _print_audit_event(event)

    elif args.audit_command == "verify":
        user = _require_auth(auth)
        results = store.verify(user.id)
        _print_verify_results(results)

    else:
        AegisError("Usage: aegis audit list|show|verify (see 'aegis audit --help')", ErrorCode.INVALID_INPUT).exit()


def _print_audit_events(events: list) -> None:
    for e in events:
        print(f"  {e.decision_id}  {e.result:<6} {e.action_type:<20} "
              f"{e.evaluated_at[:19]}  {e.agent_name}")


def _print_audit_event(e) -> None:
    print(f"Audit Version:  {e.audit_version}")
    print(f"Decision ID:    {e.decision_id}")
    print(f"Action ID:      {e.action_id}")
    print(f"Agent ID:       {e.agent_id}")
    print(f"Agent Name:     {e.agent_name}")
    print(f"Action Type:    {e.action_type}")
    print(f"Params:         {e.params}")
    print(f"Result:         {e.result}")
    print(f"Matched:        {e.matched}")
    if e.policy_id:
        print(f"Policy ID:      {e.policy_id}")
        print(f"Policy Name:    {e.policy_name}")
    if e.rule_id:
        print(f"Rule ID:        {e.rule_id}")
        print(f"Rule Effect:    {e.rule_effect}")
    print(f"Evaluated At:   {e.evaluated_at}")
    print(f"Reason:         {e.reason}")
    print(f"Previous Hash:  {e.previous_hash}")
    print(f"Hash:           {e.hash}")


# ---------------------------------------------------------------------------
# Action handlers
# ---------------------------------------------------------------------------


def _handle_action(auth: "Authenticator", args: argparse.Namespace, data_dir: str) -> None:
    if args.action_command != "evaluate":
        AegisError("Usage: aegis action evaluate <agent-id> <policy-id> <action-file>", ErrorCode.INVALID_INPUT).exit()

    from aegis.gateway import Gateway
    from aegis.models import Action

    user = _require_auth(auth)

    if not os.path.exists(args.action_file):
        AegisError(f"Action file not found: {args.action_file}", ErrorCode.NOT_FOUND).exit()

    with open(args.action_file, "r", encoding="utf-8") as f:
        import json
        try:
            raw = json.load(f)
        except json.JSONDecodeError as e:
            AegisError(f"Invalid JSON in action file: {e}", ErrorCode.INVALID_JSON).exit()

    if not isinstance(raw, dict):
        AegisError("Action file must contain a JSON object", ErrorCode.INVALID_JSON).exit()

    action_type = raw.get("action_type")
    if not isinstance(action_type, str) or not action_type.strip():
        AegisError("'action_type' is required and must be a non-empty string", ErrorCode.INVALID_INPUT).exit()

    import uuid
    action = Action(
        action_id=str(uuid.uuid4()),
        agent_id=args.agent_id,
        action_type=action_type.strip(),
        params=raw.get("params", {}),
        context=raw.get("context"),
        requested_at=datetime.now(timezone.utc),
    )

    gateway = Gateway(data_dir)
    decision = gateway.evaluate(user.id, action, args.agent_id, args.policy_id)

    print(f"Action ID:      {decision.action_id}")
    print(f"Agent ID:       {decision.agent_id}")
    print(f"Policy ID:      {args.policy_id}")
    print(f"Result:         {decision.result.value}")
    if decision.matched:
        print(f"Matched Rule:   {decision.rule_id}")
    print(f"Reason:         {decision.reason}")
    if decision.policy_name:
        print(f"Policy:         {decision.policy_name}")


# ---------------------------------------------------------------------------
# Process execution handlers
# ---------------------------------------------------------------------------


def _handle_process(auth: "Authenticator", args: argparse.Namespace, data_dir: str) -> None:
    if args.process_command == "allowlist":
        _handle_process_allowlist(auth, args, data_dir)
    elif args.process_command == "run":
        _handle_process_run(auth, args, data_dir)
    else:
        AegisError("Usage: aegis process run|allowlist (see 'aegis process --help')", ErrorCode.INVALID_INPUT).exit()


def _handle_process_allowlist(
    auth: "Authenticator", args: argparse.Namespace, data_dir: str,
) -> None:
    from aegis.execution import Allowlist, AllowlistError

    if args.allowlist_command == "add":
        user = _require_auth(auth)
        allowlist = Allowlist(data_dir)
        try:
            allowlist.add(args.name, args.path)
        except AllowlistError as e:
            AegisError(str(e), ErrorCode.ALLOWLIST_ERROR).exit()
        print(f"Allowlisted {args.name!r} -> {args.path}")

    elif args.allowlist_command == "list":
        _require_auth(auth)
        allowlist = Allowlist(data_dir)
        entries = allowlist.list()
        if not entries:
            print("No allowlisted executables.")
            return
        for e in entries:
            print(f"  {e['name']:<30} {e['path']}")

    else:
        AegisError("Usage: aegis process allowlist add|list (see 'aegis process allowlist --help')", ErrorCode.INVALID_INPUT).exit()


def _handle_process_run(
    auth: "Authenticator", args: argparse.Namespace, data_dir: str,
) -> None:
    import uuid
    from aegis.gateway import Gateway
    from aegis.models import Action, DecisionResult
    from aegis.execution import AllowlistError

    user = _require_auth(auth)

    action = Action(
        action_id=str(uuid.uuid4()),
        agent_id=args.agent_id,
        action_type="execute_process",
        params={
            "executable": args.executable_name,
            "args": list(args.process_args or []),
        },
        requested_at=datetime.now(timezone.utc),
    )

    gateway = Gateway(data_dir)
    decision, process_result = gateway.execute_process(
        user.id,
        action,
        args.agent_id,
        args.policy_id,
        executable_name=args.executable_name,
        process_args=list(args.process_args or []),
        timeout=args.timeout,
        output_limit=args.output_limit,
        cwd=args.cwd,
    )

    print(f"Action ID:      {decision.action_id}")
    print(f"Agent ID:       {decision.agent_id}")
    print(f"Policy ID:      {args.policy_id}")
    print(f"Result:         {decision.result.value}")
    if decision.matched:
        print(f"Matched Rule:   {decision.rule_id}")
    print(f"Reason:         {decision.reason}")
    if decision.policy_name:
        print(f"Policy:         {decision.policy_name}")

    if decision.result is DecisionResult.DENY:
        sys.exit(ErrorCode.PERMISSION_DENIED.value)

    if process_result is not None:
        print(f"Exit Code:      {process_result.exit_code}")
        print(f"Execution Ms:   {process_result.execution_time_ms}")
        if process_result.timed_out:
            print(f"Timed Out:      Yes")
        if process_result.output_truncated:
            print(f"Output Truncated: Yes")
        if process_result.stderr:
            print(f"Stderr:\n{process_result.stderr}", file=sys.stderr)
        if process_result.stdout:
            print(f"Stdout:\n{process_result.stdout}")


# ---------------------------------------------------------------------------
# Network handlers
# ---------------------------------------------------------------------------


def _handle_net(auth: "Authenticator", args: argparse.Namespace, data_dir: str) -> None:
    if args.net_command == "allowlist":
        _handle_net_allowlist(auth, args, data_dir)
    elif args.net_command == "request":
        _handle_net_request(auth, args, data_dir)
    else:
        AegisError("Usage: aegis net request|allowlist (see 'aegis net --help')", ErrorCode.INVALID_INPUT).exit()


def _handle_net_allowlist(
    auth: "Authenticator", args: argparse.Namespace, data_dir: str,
) -> None:
    from aegis.network import NetworkAllowlist, NetworkError

    if args.net_allow_command == "add":
        user = _require_auth(auth)
        allowlist = NetworkAllowlist(data_dir)
        try:
            allowlist.add(
                name=args.name,
                scheme=args.scheme,
                hostname=args.hostname,
                port=args.port,
                path_prefix=args.path_prefix,
            )
        except NetworkError as e:
            AegisError(str(e), ErrorCode.NETWORK_ERROR).exit()
        print(f"Allowlisted {args.scheme!r}://{args.hostname} as {args.name!r}")

    elif args.net_allow_command == "list":
        _require_auth(auth)
        allowlist = NetworkAllowlist(data_dir)
        entries = allowlist.list()
        if not entries:
            print("No allowed network destinations.")
            return
        for e in entries:
            port = f":{e['port']}" if e.get("port") else ""
            prefix = e.get("path_prefix", "/")
            print(f"  {e['name']:<30} {e['scheme']}://{e['hostname']}{port}{prefix}")

    else:
        AegisError("Usage: aegis net allowlist add|list (see 'aegis net allowlist --help')", ErrorCode.INVALID_INPUT).exit()


def _handle_net_request(
    auth: "Authenticator", args: argparse.Namespace, data_dir: str,
) -> None:
    import uuid
    from aegis.gateway import Gateway
    from aegis.models import Action, DecisionResult, HttpResponse

    user = _require_auth(auth)

    action = Action(
        action_id=str(uuid.uuid4()),
        agent_id=args.agent_id,
        action_type="http_request",
        params={
            "url": args.url,
            "method": args.method,
        },
        requested_at=datetime.now(timezone.utc),
    )

    gateway = Gateway(data_dir)
    decision, http_response = gateway.http_request(
        user.id,
        action,
        args.agent_id,
        args.policy_id,
        url=args.url,
        method=args.method,
        timeout=args.timeout,
        max_response_size=args.max_size,
    )

    print(f"Action ID:      {decision.action_id}")
    print(f"Agent ID:       {decision.agent_id}")
    print(f"Policy ID:      {args.policy_id}")
    print(f"Result:         {decision.result.value}")
    if decision.matched:
        print(f"Matched Rule:   {decision.rule_id}")
    print(f"Reason:         {decision.reason}")
    if decision.policy_name:
        print(f"Policy:         {decision.policy_name}")

    if decision.result is DecisionResult.DENY:
        sys.exit(ErrorCode.PERMISSION_DENIED.value)

    if http_response is not None:
        print(f"Status Code:    {http_response.status_code}")
        print(f"Elapsed Ms:     {http_response.elapsed_ms}")
        if http_response.timed_out:
            print(f"Timed Out:      Yes")
        if http_response.body_truncated:
            print(f"Body Truncated: Yes")
        if http_response.body:
            print(f"Response Body:\n{http_response.body}")


# ---------------------------------------------------------------------------
# AI Copilot handlers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Plan / Subscription / Entitlement handlers
# ---------------------------------------------------------------------------


def _handle_plan(auth: "Authenticator", args: argparse.Namespace, data_dir: str) -> None:
    from aegis.entitlement import EntitlementService

    _require_auth(auth)
    svc = EntitlementService(data_dir)

    if args.plan_command == "list":
        plans = svc.list_plans()
        if not plans:
            print("No plans available.")
            return
        for p in plans:
            price_display = f"{p.currency} {p.price_minor / 100:.2f}" if p.price_minor > 0 else "Free"
            print(f"  {p.id:<15} {p.name:<20} {price_display}")
        print()
        print("Use 'aegis payment submit --plan <plan-id> --utr <utr>' to purchase a subscription.")
    else:
        AegisError("Usage: aegis plan list", ErrorCode.INVALID_INPUT).exit()


def _handle_subscription(auth: "Authenticator", args: argparse.Namespace, data_dir: str) -> None:
    from aegis.entitlement import EntitlementService, EntitlementError

    user = _require_auth(auth)
    svc = EntitlementService(data_dir)

    if args.sub_command == "status":
        sub = svc.get_latest_subscription(user.id)
        if sub is None:
            print("No active subscription.")
            print("Use 'aegis payment submit --plan <plan-id> --utr <utr>' to purchase a subscription.")
            return
        plan = svc.get_plan(sub.plan_id)
        plan_name = plan.name if plan else "Unknown"
        print(f"Plan:          {plan_name} ({sub.plan_id})")
        print(f"Status:        {sub.status.value}")
        print(f"Started:       {sub.start_time.isoformat()}")
        if sub.end_time:
            print(f"Ends:          {sub.end_time.isoformat()}")
        print(f"Auto-renew:    {'Yes' if sub.renewal else 'No'}")

    elif args.sub_command == "activate":
        if not is_dev_mode():
            AegisError("subscription activation is a development-only command. "
                       "Use 'aegis payment submit --plan <plan-id> --utr <utr>' "
                       "to purchase a subscription.",
                       ErrorCode.CONFIG_ERROR).exit()
        try:
            sub = svc.activate_subscription(
                user.id, args.plan_id, caller_id=user.id,
            )
        except EntitlementError as e:
            AegisError(str(e), ErrorCode.ENTITLEMENT_ERROR).exit()
        plan = svc.get_plan(sub.plan_id)
        plan_name = plan.name if plan else "Unknown"
        print(f"Subscribed to {plan_name} ({sub.plan_id})")
    else:
        AegisError("Usage: aegis subscription status|activate", ErrorCode.INVALID_INPUT).exit()


def _handle_entitlement(auth: "Authenticator", args: argparse.Namespace, data_dir: str) -> None:
    from aegis.entitlement import EntitlementService

    user = _require_auth(auth)
    svc = EntitlementService(data_dir)

    if args.ent_command == "list":
        info = svc.list_entitlements(user.id)
        if not info:
            print("No active subscription or no entitlements found.")
            return
        sub = svc.get_latest_subscription(user.id)
        plan_name = svc.get_plan(sub.plan_id).name if sub and sub.plan_id else "Unknown"
        print(f"Subscription:  {sub.plan_id if sub else 'None'} ({plan_name})")
        print(f"Status:        {sub.status.value if sub else 'None'}")
        print()
        print("Entitlements:")
        for key, value in sorted(info.items()):
            print(f"  {key:<25} {value}")
        print()
        print("Note: Entitlements control feature availability.")
        print("Aegis policy decisions are separate and remain the")
        print("final security authority.")
    else:
        AegisError("Usage: aegis entitlement list", ErrorCode.INVALID_INPUT).exit()


def _handle_payment(auth: "Authenticator", args: argparse.Namespace, data_dir: str) -> None:
    from aegis.payment import PaymentService, PaymentError

    user = _require_auth(auth)

    svc = PaymentService(data_dir)

    if args.pay_command == "submit":
        try:
            payment = svc.submit_payment(user.id, args.plan, args.utr)
        except PaymentError as e:
            AegisError(str(e), ErrorCode.PAYMENT_ERROR).exit()
        print(f"Payment submitted: {payment.payment_id}")
        print(f"Plan:             {payment.plan_id}")
        print(f"Amount:           {payment.currency} {payment.amount_minor / 100:.2f}")
        print(f"Destination UPI:  {payment.destination_upi}")
        print(f"UTR:              {redact_utr(payment.submitted_utr)}")
        print(f"Status:           {payment.status.value}")
        print()
        print("Your payment is PENDING verification.")
        print("An authorized verifier will review it manually.")

    elif args.pay_command == "status":
        try:
            payment = svc.get_payment(args.payment_id, user.id)
        except PaymentError as e:
            AegisError(str(e), ErrorCode.PAYMENT_ERROR).exit()
        print(f"Payment ID:       {payment.payment_id}")
        print(f"Plan:             {payment.plan_id}")
        print(f"Amount:           {payment.currency} {payment.amount_minor / 100:.2f}")
        print(f"Destination UPI:  {payment.destination_upi}")
        print(f"UTR:              {redact_utr(payment.submitted_utr)}")
        print(f"Submitted:        {payment.submitted_at.isoformat()}")
        print(f"Status:           {payment.status.value}")
        if payment.verification_method:
            print(f"Verified via:     {payment.verification_method}")
        if payment.verified_at:
            print(f"Verified at:      {payment.verified_at.isoformat()}")
        if payment.rejection_reason:
            print(f"Rejection reason: {payment.rejection_reason}")

    elif args.pay_command == "list":
        payments = svc.list_payments(user.id)
        if not payments:
            print("No payment records found.")
            return
        for p in payments:
            print(f"  {p.payment_id:<40} {p.plan_id:<12} {p.status.value:<10} {p.submitted_at.isoformat()}")
    else:
        AegisError("Usage: aegis payment submit|status|list", ErrorCode.INVALID_INPUT).exit()


def _handle_auth(auth: "Authenticator", args: argparse.Namespace, data_dir: str) -> None:
    from aegis.rbac import AuthorizationService

    if args.auth_command == "whoami":
        user = _require_auth(auth)
        print(f"Authenticated as {user.username!r} (id={user.id}, role={user.role})")

    elif args.auth_command == "permissions":
        user = _require_auth(auth)
        authz = AuthorizationService(data_dir)
        perms = authz.list_user_permissions(user.id)
        print(f"User:       {user.username!r} (id={user.id})")
        print(f"Role:       {user.role}")
        print("Permissions:")
        if perms:
            for p in sorted(perms):
                print(f"  - {p}")
        else:
            print("  (none)")

    elif args.auth_command == "mfa":
        _handle_mfa(auth, args, data_dir)

    else:
        AegisError("Usage: aegis auth whoami|permissions|mfa", ErrorCode.INVALID_INPUT).exit()


def _handle_mfa(auth: "Authenticator", args: argparse.Namespace, data_dir: str) -> None:
    from aegis.rbac import AuthorizationService

    if args.mfa_command == "status":
        user = _require_auth(auth)
        print(f"MFA enabled:      {user.mfa_enabled}")
        if user.totp_confirmed_at:
            print(f"TOTP confirmed:   {user.totp_confirmed_at.isoformat()}")
        else:
            print("TOTP confirmed:   No")
        print(f"Recovery codes:   {len(user.recovery_codes)} remaining")
        if user.recovery_codes_generated_at:
            print(f"Codes generated:  {user.recovery_codes_generated_at.isoformat()}")

    elif args.mfa_command == "enable":
        user = _require_auth(auth)
        if user.mfa_enabled:
            AegisError("MFA is already enabled. Disable it first to reconfigure.", ErrorCode.CONFLICT).exit()

        username = args.username or user.username
        secret, uri = auth.generate_totp_secret(username)
        auth.enable_mfa(user.id, user.password_hash, secret)

        print(f"MFA setup initiated for {username!r}")
        print()
        print("Scan the following URI with your authenticator app (e.g. Google Authenticator):")
        print(f"  {uri}")
        print()
        print(f"Or enter the secret key manually: {secret}")
        print()
        print("Then run 'aegis auth mfa confirm <code>' with a TOTP code from your app.")
        print("We recommend also running 'aegis auth mfa regenerate-recovery-codes' after confirming.")

    elif args.mfa_command == "confirm":
        user = _require_auth(auth)
        if user.mfa_enabled:
            AegisError("MFA is already enabled.", ErrorCode.CONFLICT).exit()
        if not user.totp_secret:
            AegisError("No TOTP secret found. Run 'aegis auth mfa enable' first.", ErrorCode.INVALID_INPUT).exit()

        try:
            updated = auth.confirm_mfa(user.id, args.code)
        except ValueError as e:
            AegisError(str(e), ErrorCode.INVALID_INPUT).exit()

        print("MFA enabled successfully!")

        # Generate recovery codes automatically
        _, raw_codes = auth.regenerate_recovery_codes(user.id)
        print()
        print("Recovery codes generated. Store these securely:")
        for i, code in enumerate(raw_codes, 1):
            print(f"  {i}. {code}")
        print()
        print("Each code can be used once if you lose access to your authenticator app.")

    elif args.mfa_command == "disable":
        user = _require_auth(auth)
        if not user.mfa_enabled:
            AegisError("MFA is not enabled.", ErrorCode.INVALID_INPUT).exit()

        auth.disable_mfa(user.id)
        print("MFA disabled.")

    elif args.mfa_command == "regenerate-recovery-codes":
        user = _require_auth(auth)
        if not user.mfa_enabled:
            AegisError("MFA is not enabled. Enable MFA first.", ErrorCode.INVALID_INPUT).exit()

        _, raw_codes = auth.regenerate_recovery_codes(user.id)
        print("New recovery codes generated. Store these securely:")
        for i, code in enumerate(raw_codes, 1):
            print(f"  {i}. {code}")
        print()
        print("Previous recovery codes are no longer valid.")
        print("Each code can be used once if you lose access to your authenticator app.")

    else:
        AegisError("Usage: aegis auth mfa status|enable|confirm|disable|regenerate-recovery-codes", ErrorCode.INVALID_INPUT).exit()


def _handle_admin(auth: "Authenticator", args: argparse.Namespace, data_dir: str) -> None:
    from aegis.payment import PaymentService, PaymentError
    from aegis.rbac import AuthorizationError

    user = _require_auth(auth)
    svc = PaymentService(data_dir)

    if args.admin_command == "payment":
        if args.admin_payment_command == "verify":
            try:
                payment = svc.verify_payment(
                    payment_id=args.payment_id,
                    verifier_id=user.id,
                )
            except (PaymentError, AuthorizationError) as e:
                AegisError(str(e), ErrorCode.PAYMENT_ERROR).exit()
            print(f"Payment VERIFIED: {payment.payment_id}")
            print(f"Plan:             {payment.plan_id}")
            print(f"Status:           {payment.status.value}")
            print(f"Verified at:      {payment.verified_at.isoformat()}")
            print("Subscription activated.")

        elif args.admin_payment_command == "reject":
            try:
                payment = svc.reject_payment(
                    payment_id=args.payment_id,
                    verifier_id=user.id,
                    reason=args.reason,
                )
            except (PaymentError, AuthorizationError) as e:
                AegisError(str(e), ErrorCode.PAYMENT_ERROR).exit()
            print(f"Payment REJECTED: {payment.payment_id}")
            print(f"Reason:           {payment.rejection_reason}")

        else:
            AegisError("Usage: aegis admin payment verify|reject", ErrorCode.INVALID_INPUT).exit()

    else:
        AegisError("Usage: aegis admin payment", ErrorCode.INVALID_INPUT).exit()


def _handle_ai(auth: "Authenticator", args: argparse.Namespace, data_dir: str) -> None:
    from aegis.ai import AICopilot, AIError
    from aegis.entitlement import EntitlementService, EntitlementError

    user = _require_auth(auth)

    if args.ai_command in ("explain", "audit-summary", "policy-review", "policy-draft"):
        svc = EntitlementService(data_dir)
        try:
            svc.require(user.id, "ai.copilot")
        except EntitlementError:
            AegisError("AI Copilot is not available on your plan.", ErrorCode.ENTITLEMENT_ERROR).exit()

    copilot = AICopilot(data_dir)

    try:
        if args.ai_command == "explain":
            result = copilot.explain_decision(args.decision_id, user.id)
            copilot.record_audit(user.id, copilot._outcomes[-1])
            print(result)

        elif args.ai_command == "audit-summary":
            result = copilot.audit_summary(user.id)
            copilot.record_audit(user.id, copilot._outcomes[-1])
            print(result)

        elif args.ai_command == "policy-review":
            result = copilot.policy_review(args.policy_id, user.id)
            copilot.record_audit(user.id, copilot._outcomes[-1])
            print(result)

        elif args.ai_command == "policy-draft":
            result = copilot.policy_draft(args.description, user.id)
            copilot.record_audit(user.id, copilot._outcomes[-1])
            print(result)

        else:
            AegisError("Usage: aegis ai explain|audit-summary|policy-review|policy-draft", ErrorCode.INVALID_INPUT).exit()

    except AIError as e:
        AegisError(str(e), ErrorCode.AI_ERROR).exit()


# ---------------------------------------------------------------------------
# Database handlers
# ---------------------------------------------------------------------------


def _handle_serve(args: argparse.Namespace) -> None:
    """Start the Aegis API server."""
    import uvicorn
    from aegis.api.app import create_app

    cors_origins = None
    if args.cors_origins:
        cors_origins = [o.strip() for o in args.cors_origins.split(",")]

    app = create_app(cors_origins=cors_origins)
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


def _handle_db(args: argparse.Namespace, data_dir: str) -> None:
    if args.db_command == "migrate":
        from aegis.persistence.migration import migrate, verify_migration
        result = migrate(data_dir, rebuild=args.rebuild)
        print(result.summary())
        counts = verify_migration(data_dir)
        print()
        print("Verification (source → database):")
        all_ok = True
        for entity, pair in counts.items():
            match = "✓" if pair["ndjson"] == pair["db"] else "✗"
            if match == "✗":
                all_ok = False
            print(f"  {match} {entity:<15} NDJSON={pair['ndjson']}  DB={pair['db']}")
        if all_ok:
            print("\nAll counts match. Migration verified successfully.")
        else:
            print("\nWARNING: Some counts differ. Review the output above.", file=sys.stderr)
            sys.exit(ErrorCode.INTEGRITY_ERROR.value)
    else:
        AegisError("Usage: aegis db migrate [--rebuild]", ErrorCode.INVALID_INPUT).exit()


# ---------------------------------------------------------------------------
# Backup handlers
# ---------------------------------------------------------------------------


def _handle_backup(args: argparse.Namespace, data_dir: str) -> None:
    from aegis.backup import create_backup, list_backups, restore_backup

    if args.backup_command == "create":
        path = create_backup(data_dir)
        size = os.path.getsize(path)
        print(f"Backup created: {path}")
        print(f"Size:          {size:,} bytes")

    elif args.backup_command == "list":
        backups = list_backups(data_dir)
        if not backups:
            print("No backups found.")
            return
        for b in backups:
            size_kb = b["size_bytes"] / 1024
            print(f"  {b['name']:<50} {size_kb:>8.1f} KB  {b['created'][:19]}")

    elif args.backup_command == "restore":
        try:
            summary = restore_backup(data_dir, args.backup_path)
            print(f"Restore complete: {summary}")
        except (FileNotFoundError, ValueError) as e:
            AegisError(str(e), ErrorCode.IO_ERROR).exit()
    else:
        AegisError("Usage: aegis backup create|list|restore", ErrorCode.INVALID_INPUT).exit()


# ---------------------------------------------------------------------------
# Filesystem handlers
# ---------------------------------------------------------------------------


def _handle_fs(auth: "Authenticator", args: argparse.Namespace, data_dir: str) -> None:
    if args.fs_command != "read":
        AegisError("Usage: aegis fs read <agent-id> <policy-id> <path>", ErrorCode.INVALID_INPUT).exit()

    from aegis.gateway import Gateway
    from aegis.models import Action, DecisionResult
    from aegis.fs import Filesystem, FsError

    user = _require_auth(auth)

    action = Action(
        action_id=str(uuid.uuid4()),
        agent_id=args.agent_id,
        action_type="fs_read",
        params={"path": args.path},
        requested_at=datetime.now(timezone.utc),
    )

    gateway = Gateway(data_dir)
    decision = gateway.evaluate(user.id, action, args.agent_id, args.policy_id)

    if decision.result is DecisionResult.DENY:
        AegisError(f"DENY: {decision.reason}", ErrorCode.PERMISSION_DENIED).exit()

    fs = Filesystem(data_dir)
    try:
        content = fs.read_file(args.path)
    except FsError as e:
        AegisError(str(e), ErrorCode.FS_ERROR).exit()

    print(content, end="")  # file contents — no trailing newline added


def _print_verify_results(results: list[dict]) -> None:
    valid_count = sum(1 for r in results if r["valid"])
    invalid_count = sum(1 for r in results if not r["valid"])
    total = len(results)
    print(f"Chain: {valid_count}/{total} events valid")
    if invalid_count:
        print(f"WARNING: {invalid_count} integrity violation(s) detected!")
    for r in results:
        status = "OK" if r["valid"] else "FAIL"
        print(f"  [{status}] event #{r['index']} ({r['decision_id']})")
        if not r["valid"] and r["error"]:
            print(f"         {r['error']}")
