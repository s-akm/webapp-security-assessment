# Django のビュー。ガードのある側と無い側。
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
import os

@login_required
def dashboard(request):
    return JsonResponse({"ok": True})

def report(request):           # ガードが無い
    send_mail(to=request.POST["email"])
    return JsonResponse({"ok": True})

DEBUG = os.getenv("DEBUG") != "false"          # fail-open（5 節）
QUERY = "select * from users where id = %s" % request.GET.get("id")  # 危険（3 節）
