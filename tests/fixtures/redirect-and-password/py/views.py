# 架空の題材: Django の戻り先
from django.http import HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme


def login_view(request):
    goto = request.GET.get('next', '/')
    return HttpResponseRedirect(goto)


def login_safe(request):
    goto = request.GET.get('next', '/')
    if not url_has_allowed_host_and_scheme(goto, allowed_hosts={request.get_host()}):
        goto = '/'
    return HttpResponseRedirect(goto)
