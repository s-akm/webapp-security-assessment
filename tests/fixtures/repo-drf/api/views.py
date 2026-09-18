from rest_framework import viewsets, permissions

class UserViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated]
    queryset = User.objects.all()

class ReportViewSet(viewsets.ModelViewSet):
    queryset = Report.objects.all()

    def create(self, request):
        send_mail(request.data["email"])
        return Response({"ok": True})
