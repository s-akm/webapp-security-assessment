@app.route("/hello")
def hello():
    return render_template_string(f"<p>Hello {request.args.get('who')}</p>")


def card(tpl_text, env):
    return env.from_string(tpl_text).render()


def footer(env):
    return env.from_string("<footer>(c)</footer>").render()
