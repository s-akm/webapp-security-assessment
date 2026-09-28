import os
DENIED_SUFFIXES = {".php", ".phtml"}

def attach(request):
    f = request.FILES["doc"]
    if os.path.splitext(f.name)[1] in DENIED_SUFFIXES:
        raise ValueError("not accepted")
