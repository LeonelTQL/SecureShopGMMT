"""Controlled paired cases, authored for this advance, not extracted from production.

Each tuple is (vulnerable, mitigated) under the contract in docs/fuentes.md.
No example is executed. Related language/API/template variants share a split group.
"""
from .common import clean_code, digest

CASES = {
    "object_authorization": ("CWE-639", "A01:2025", "API1:2023", [
        ("def read_order(order_id, user):\n    return orders.get(order_id)",
         "def read_order(order_id, user):\n    order = orders.get(order_id)\n    if order.owner_id != user.id:\n        raise PermissionError()\n    return order"),
        ("def invoice(invoice_id, user):\n    return Invoice.query.filter_by(id=invoice_id).first()",
         "def invoice(invoice_id, user):\n    return Invoice.query.filter_by(id=invoice_id, owner_id=user.id).first()"),
        ("def download(document_id, user):\n    document = documents.find_one({'id': document_id})\n    return document.content",
         "def download(document_id, user):\n    document = documents.find_one({'id': document_id, 'owner_id': user.id})\n    if document is None:\n        raise PermissionError()\n    return document.content"),
        ("def view_profile(profile_id, user):\n    return profiles[profile_id]",
         "def view_profile(profile_id, user):\n    if profile_id not in user.permitted_profile_ids:\n        raise PermissionError()\n    return profiles[profile_id]"),
        ("def get_message(message_id, user):\n    message = Message.objects.get(pk=message_id)\n    return message.serialize()",
         "def get_message(message_id, user):\n    message = Message.objects.get(pk=message_id, recipient_id=user.id)\n    return message.serialize()"),
        ("def read_account(account_id, user):\n    account = accounts.load(account_id)\n    return account.balance",
         "def read_account(account_id, user):\n    account = accounts.load(account_id)\n    authorize(user, 'read', account)\n    return account.balance"),
        ("def get_ticket(ticket_id, user):\n    ticket = tickets.fetch(ticket_id)\n    return ticket.details",
         "def get_ticket(ticket_id, user):\n    ticket = tickets.fetch(ticket_id)\n    if ticket.tenant_id != user.tenant_id:\n        raise PermissionError()\n    return ticket.details"),
    ]),
    "authentication": ("CWE-287", "A07:2025", "API2:2023", [
        ("def identity(token):\n    return jwt.decode(token, options={'verify_signature': False})",
         "def identity(token):\n    return jwt.decode(token, public_key, algorithms=['RS256'], audience='orders', issuer='identity')"),
        ("def identity(token):\n    return jose.jwt.get_unverified_claims(token)",
         "def identity(token):\n    return jose.jwt.decode(token, public_key, algorithms=['RS256'], audience='orders', issuer='identity')"),
        ("def identity(request):\n    return {'user': request.headers['X-User-Id']}",
         "def identity(request):\n    token = request.headers['Authorization']\n    return verify_access_token(token)"),
        ("def identity(token):\n    return json.loads(base64.b64decode(token))",
         "def identity(token):\n    value = signer.unsign(token, max_age=900)\n    return json.loads(value)"),
        ("def identity(cookie):\n    return json.loads(cookie)",
         "def identity(cookie):\n    return signed_serializer.loads(cookie, max_age=900)"),
        ("def login(password, account):\n    return password == account.password",
         "def login(password, account):\n    rate_limiter.check(account.id)\n    return bcrypt.checkpw(password.encode(), account.password_hash)"),
        ("def identity(request):\n    return request.args['username']",
         "def identity(request):\n    session_id = request.cookies['session']\n    return sessions.require_authenticated(session_id)"),
    ]),
    "property_authorization": ("CWE-862", "A01:2025", "API3:2023", [
        ("def update(user, payload):\n    for key, value in payload.items():\n        setattr(user, key, value)",
         "def update(user, payload):\n    for key in ('display_name', 'language'):\n        if key in payload:\n            setattr(user, key, payload[key])"),
        ("def update(user, payload):\n    user.__dict__.update(payload)",
         "def update(user, payload):\n    user.display_name = payload['display_name']"),
        ("def update(user, payload):\n    User.objects.filter(id=user.id).update(**payload)",
         "def update(user, payload):\n    User.objects.filter(id=user.id).update(display_name=payload['display_name'])"),
        ("def update(user, payload):\n    changes = dict(payload)\n    repository.patch(user.id, changes)",
         "def update(user, payload):\n    changes = {key: payload[key] for key in ('display_name', 'timezone') if key in payload}\n    repository.patch(user.id, changes)"),
        ("def update(user, payload):\n    user.apply_attributes(payload)\n    user.save()",
         "def update(user, payload):\n    user.apply_attributes(profile_schema.validate(payload, forbid_extra=True))\n    user.save()"),
        ("def update(user, payload):\n    return accounts.update_one({'id': user.id}, {'$set': payload})",
         "def update(user, payload):\n    return accounts.update_one({'id': user.id}, {'$set': {'language': payload['language']}})"),
        ("def update(user, payload):\n    model = Profile(**payload)\n    user.merge(model)",
         "def update(user, payload):\n    model = Profile(display_name=payload['display_name'])\n    user.merge(model)"),
    ]),
    "function_authorization": ("CWE-862", "A01:2025", "API5:2023", [
        ("def delete_users(user):\n    return repository.delete_all()",
         "def delete_users(user):\n    if user.role != 'admin':\n        raise PermissionError()\n    return repository.delete_all()"),
        ("def export_database(user):\n    return database.export()",
         "def export_database(user):\n    require_permission(user, 'database:export')\n    return database.export()"),
        ("def set_role(user, target, role):\n    target.role = role\n    target.save()",
         "def set_role(user, target, role):\n    if not user.has_permission('roles:write'):\n        raise PermissionError()\n    target.role = role\n    target.save()"),
        ("def reset_system(user):\n    system.reset()",
         "@require_role('admin')\ndef reset_system(user):\n    system.reset()"),
        ("def purge_audit(user):\n    audit.clear()\n    return True",
         "def purge_audit(user):\n    policy.enforce(user, 'audit:purge')\n    audit.clear()\n    return True"),
        ("def change_settings(user, data):\n    settings.update(data)",
         "def change_settings(user, data):\n    if 'settings:write' not in user.permissions:\n        raise PermissionError()\n    settings.update(data)"),
        ("def stop_service(user, service_id):\n    orchestrator.stop(service_id)",
         "def stop_service(user, service_id):\n    access_control.require(user, 'services:stop')\n    orchestrator.stop(service_id)"),
    ]),
    "configuration": ("CWE-489", "A02:2025", "API8:2023", [
        ("app = Flask(__name__)\napp.run(debug=True)", "app = Flask(__name__)\napp.run(debug=False)"),
        ("app = FastAPI(debug=True)", "app = FastAPI(debug=False)"),
        ("DEBUG = True\nALLOWED_HOSTS = ['api.example.test']", "DEBUG = False\nALLOWED_HOSTS = ['api.example.test']"),
        ("app.config.update(DEBUG=True, TESTING=False)", "app.config.update(DEBUG=False, TESTING=False)"),
        ("application.settings['debug'] = True", "application.settings['debug'] = False"),
        ("config = {'debug': True, 'environment': 'production'}\nserver.start(config)",
         "config = {'debug': False, 'environment': 'production'}\nserver.start(config)"),
        ("server = make_server(debug=True)\nserver.serve()", "server = make_server(debug=False)\nserver.serve()"),
    ]),
}


def records():
    rows = []
    for family, (cwe, top, api, pairs) in CASES.items():
        for i, pair in enumerate(pairs):
            # Same ordinal across families stays together, so no pair crosses splits.
            split = "train" if i < 5 else "validation" if i == 5 else "test"
            for vulnerable, snippet in ((1, pair[0]), (0, pair[1])):
                code = clean_code(snippet)
                rows.append({"record_id": f"control-{family}-{i}-{vulnerable}", "code": code,
                             "language": "Python", "artifact_type": "configuration" if family == 'configuration' else 'source',
                             "source": "controlled", "project": f"controlled-template-{i}",
                             "source_url": "src/controlled.py", "source_revision": digest(code),
                             "license": "CC0-1.0", "scenario": family, "cwe": cwe,
                             "vulnerable": vulnerable, "labels": [top, api] if vulnerable else [],
                             "group": f"controlled-template-{i}", "split": split,
                             "label_basis": "Par didáctico por construcción; contrato y limitaciones en docs/fuentes.md",
                             "review_status": "pendiente_revision_humana"})
    return rows
