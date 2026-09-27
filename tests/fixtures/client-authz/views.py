def promote(request):
    if request.data.get('is_staff'):
        user.is_staff = True

def update_profile(request):
    User.objects.filter(pk=request.user.pk).update(**request.data)
