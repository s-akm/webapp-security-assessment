import tornado.web

class AdminHandler(tornado.web.RequestHandler):
    @tornado.web.authenticated
    def get(self):
        self.write({"ok": True})

class ReportHandler(tornado.web.RequestHandler):
    def post(self):
        send_mail(self.get_argument("email"))
        self.write({"ok": True})
