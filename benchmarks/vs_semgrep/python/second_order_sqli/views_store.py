from django.http import JsonResponse
from django.views import View
from .models import UserProfile


class UpdateProfileView(View):
    def post(self, request):
        username = request.POST.get("username")
        bio = request.POST.get("bio")

        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        profile.display_name = username
        profile.bio = bio
        profile.save()

        return JsonResponse({"status": "ok"})
