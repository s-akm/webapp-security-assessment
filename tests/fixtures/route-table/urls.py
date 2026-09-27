urlpatterns = [path('media/<path:path>', serve, {'document_root': MEDIA_ROOT, 'show_indexes': True})]
