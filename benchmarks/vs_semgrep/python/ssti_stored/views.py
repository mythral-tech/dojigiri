from flask import Flask, request, jsonify
from jinja2 import Environment
from .models import db, EmailTemplate

app = Flask(__name__)
jinja_env = Environment()


@app.route("/templates", methods=["POST"])
def create_template():
    data = request.json
    tpl = EmailTemplate(
        name=data["name"],
        subject=data["subject"],
        body=data["body"],
        created_by=data["user_id"],
    )
    db.session.add(tpl)
    db.session.commit()
    return jsonify({"id": tpl.id})


@app.route("/preview/<int:template_id>")
def preview_template(template_id):
    tpl = EmailTemplate.query.get_or_404(template_id)

    rendered_subject = jinja_env.from_string(tpl.subject).render(
        user_name="Test User", company="Acme"
    )
    rendered_body = jinja_env.from_string(tpl.body).render(
        user_name="Test User", company="Acme"
    )

    return jsonify({"subject": rendered_subject, "body": rendered_body})
