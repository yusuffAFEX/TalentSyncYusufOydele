import profile

from django.contrib.auth.models import User
from django.db import models

# Create your models here.
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.urls import reverse
from PIL import Image


class ActivePost(models.Manager):
    def get_queryset(self):
        return super(ActivePost, self).get_queryset().filter(is_deleted=False)


class Post(models.Model):
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    content = models.TextField()
    date_created = models.DateTimeField(auto_now_add=True)
    slug = models.SlugField()
    image = models.ImageField(null=True, blank=True, upload_to='post')
    is_deleted = models.BooleanField(default=False)

    objects = models.Manager()
    post_objects = ActivePost()

    def __str__(self):
        return self.title

    def get_absolute_url(self):
        return reverse('post-detail', args=[str(self.slug)])


class ActiveComment(models.Manager):
    def get_queryset(self):
        return super(ActiveComment, self).get_queryset().filter(is_hidden=False)


class Comment(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    text = models.TextField()
    email = models.EmailField(editable=False)
    date = models.DateTimeField(auto_now_add=True)
    is_hidden = models.BooleanField(default=False)

    objects = models.Manager()
    comment_objects = ActiveComment()

    def __str__(self):
        return f'{self.user.first_name}, {self.user.last_name}'


class Profile(models.Model):
    image = models.ImageField(null=True, blank=True, upload_to='media/photos')
    author = models.OneToOneField(User, on_delete=models.CASCADE)

    def __str__(self):
        return f'{self.author.first_name} Profile'

    def save(self, *args, **kwargs):
        super(Profile, self).save()
        if self.image:
            image = Image.open(self.image.path)
            if image.height > 300 and image.width > 300:
                size = (200, 200)
                image.thumbnail(size)
                image.save(self.image.path)


@receiver(post_save, sender=User)
def create_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(author=instance)