from django.shortcuts import get_object_or_404, render
from .models import Account, Document, Entry


@login_required
def account_page(request, account_id):
    account = Account.objects.get(pk=account_id)
    entries = Entry.objects.filter(account_id=account.id)
    return render(request, "account.html", {"current_user": account.holder, "entries": entries})


@login_required
def document_detail(request, doc_id):
    doc = get_object_or_404(Document, pk=doc_id, owner=request.user)
    return render(request, "doc.html", {"doc": doc})
