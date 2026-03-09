from django.db import connection
from django.http import JsonResponse
from django.views import View
from .models import UserProfile


class ProfileSearchView(View):
    def get(self, request):
        profile = UserProfile.objects.get(user=request.user)
        display_name = profile.display_name

        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT * FROM audit_log WHERE actor = '{display_name}'"
            )
            rows = cursor.fetchall()

        return JsonResponse({"logs": rows})
